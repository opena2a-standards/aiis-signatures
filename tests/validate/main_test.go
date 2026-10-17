package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const repoRoot = "../.."

func schemaForTest(t *testing.T) *jsonschema.Schema {
	t.Helper()
	sch, err := compileSchema(filepath.Join(repoRoot, filepath.FromSlash(schemaPath)))
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

// A schema 0.1 shaped document must be rejected by schema 0.2.
func TestSchema01ShapedDocumentFails(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "schema-0.1-shaped.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ls, err := parseSignature(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = schemaForTest(t).Validate(ls.raw)
	if err == nil {
		t.Fatal("schema 0.1 shaped document validated against schema 0.2; it must fail")
	}
	msg := err.Error()
	for _, want := range []string{"technique_ids", "schema_version"} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not mention %q:\n%s", want, msg)
		}
	}
}

// The corpus as committed passes every check.
func TestCorpusPasses(t *testing.T) {
	var out bytes.Buffer
	if code := run(repoRoot, false, &out); code != 0 {
		t.Fatalf("validator exit %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "13 of 13 checks reported, 0 failure(s)") {
		t.Fatalf("unexpected summary:\n%s", out.String())
	}
}

// Targeted rejections: each mutation of a valid signature must fail the
// schema with a message naming the offending field.
func TestSchemaRejections(t *testing.T) {
	sch := schemaForTest(t)
	injection := mustLoad(t, "signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml")
	exposure := mustLoad(t, "signatures/exposure/AIIS-EXPOSURE-CHROMA-HEARTBEAT-01.yaml")
	for _, doc := range []map[string]any{injection, exposure} {
		if err := sch.Validate(doc); err != nil {
			t.Fatalf("baseline must validate: %v", err)
		}
	}
	cases := []struct {
		name   string
		base   map[string]any
		mutate func(m map[string]any)
		want   string
	}{
		{"exposure with attack_class", exposure, func(m map[string]any) { m["attack_class"] = "lateral_movement" }, "attack_class"},
		{"injection lacking attack_vector", injection, func(m map[string]any) { delete(m, "attack_vector") }, "attack_vector"},
		{"active without provenance", injection, func(m map[string]any) { delete(m, "provenance") }, "provenance"},
		{"numeric id AIIS-0001", injection, func(m map[string]any) { m["id"] = "AIIS-0001" }, "id"},
		{"leftover technique_ids", injection, func(m map[string]any) { m["technique_ids"] = []any{"T-2001"} }, "technique_ids"},
		{"injection with exposure_class", injection, func(m map[string]any) { m["exposure_class"] = "EXPOSURE-MCP-SERVER" }, "exposure_class"},
		{"exposure lacking exposure_class", exposure, func(m map[string]any) { delete(m, "exposure_class") }, "exposure_class"},
		{"deprecated status", injection, func(m map[string]any) { m["status"] = "deprecated" }, "status"},
		{"schema_version 0.1", injection, func(m map[string]any) { m["schema_version"] = "0.1" }, "schema_version"},
		{"missing category", injection, func(m map[string]any) { delete(m, "category") }, "category"},
		{"hma check id outside the grammar", injection, func(m map[string]any) { m["hma_check_ids"] = []any{"sem-inst-002"} }, "hma_check_ids"},
		{"bad provenance tier", injection, func(m map[string]any) {
			m["provenance"] = map[string]any{"evidence_tier": "guessed"}
		}, "evidence_tier"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := clone(t, tc.base)
			tc.mutate(doc)
			err := sch.Validate(doc)
			if err == nil {
				t.Fatalf("%s: validated, must fail", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: rejection does not mention %q:\n%v", tc.name, tc.want, err)
			}
		})
	}
}

// Extension keys prefixed x_ are admitted; any other unknown key is not.
func TestSchemaExtensions(t *testing.T) {
	sch := schemaForTest(t)
	base := mustLoad(t, "signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml")
	doc := clone(t, base)
	doc["x_vendor_note"] = map[string]any{"anything": true}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("x_ extension rejected: %v", err)
	}
	doc = clone(t, base)
	doc["vendor_note"] = "no"
	if err := sch.Validate(doc); err == nil {
		t.Error("unknown key accepted")
	}
}

// The four match types behave as specified.
func TestMatchers(t *testing.T) {
	tag := func(cps ...rune) string { return string(cps) }
	england := tag(0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F)
	cases := []struct {
		name string
		spec MatchSpec
		doc  string
		want bool
	}{
		{"regex", MatchSpec{Type: "regex", Pattern: `ignore\s+previous`}, "please IGNORE previous", false},
		{"regex flags", MatchSpec{Type: "regex", Pattern: `ignore\s+previous`, Flags: "i"}, "please IGNORE previous", true},
		{"substring default case insensitive", MatchSpec{Type: "substring", Contains: []string{"<|system|>"}}, "x <|SYSTEM|> y", true},
		{"substring case sensitive", MatchSpec{Type: "substring", Contains: []string{"<|system|>"}, CaseSensitive: true}, "x <|SYSTEM|> y", false},
		{"substring any needle", MatchSpec{Type: "substring", Contains: []string{"aaa", "bbb"}}, "xx bbb", true},
		{"unicode default min 1", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}}, "a" + tag(0xE0041), true},
		{"unicode min 3 short", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}, MinMatches: 3}, tag(0xE0041, 0xE0042), false},
		{"unicode min 3 met", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}, MinMatches: 3}, tag(0xE0041, 0xE0042, 0xE0043), true},
		{"unicode flag counted without exclusion", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}, MinMatches: 3}, england, true},
		{"unicode flag stripped", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}, MinMatches: 3, ExcludeEmojiTagFlags: true}, england, false},
		{"unicode payload beside flag", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}, MinMatches: 3, ExcludeEmojiTagFlags: true}, england + tag(0xE0041, 0xE0042, 0xE0043), true},
		{"unicode flag wrapper with payload body", MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: tag(0xE0000), To: tag(0xE007F)}}, MinMatches: 3, ExcludeEmojiTagFlags: true}, tag(0x1F3F4, 0xE0069, 0xE0067, 0xE006E, 0xE007F), true},
		{"composite all_of", MatchSpec{Type: "composite", AllOf: []MatchSpec{{Type: "substring", Contains: []string{"a"}}, {Type: "substring", Contains: []string{"b"}}}}, "a only", false},
		{"composite all_of met", MatchSpec{Type: "composite", AllOf: []MatchSpec{{Type: "substring", Contains: []string{"a"}}, {Type: "substring", Contains: []string{"b"}}}}, "a and b", true},
		{"composite any_of", MatchSpec{Type: "composite", AnyOf: []MatchSpec{{Type: "substring", Contains: []string{"a"}}, {Type: "regex", Pattern: "^b"}}}, "b first", true},
		{"composite nested", MatchSpec{Type: "composite", AllOf: []MatchSpec{{Type: "substring", Contains: []string{"x"}}, {Type: "composite", AnyOf: []MatchSpec{{Type: "substring", Contains: []string{"y"}}, {Type: "substring", Contains: []string{"z"}}}}}}, "x z", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatch(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Match(tc.doc); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.doc, got, tc.want)
			}
		})
	}
	bad := []MatchSpec{
		{Type: "regex", Pattern: "("},
		{Type: "substring"},
		{Type: "unicode_range"},
		{Type: "unicode_range", Ranges: []UnicodeRange{{From: "ab", To: "c"}}},
		{Type: "composite"},
		{Type: "css_selector"},
	}
	for _, spec := range bad {
		if _, err := compileMatch(spec); err == nil {
			t.Errorf("%+v compiled, must fail", spec)
		}
	}
}

// A use case in docs/use-cases.md that names a surface type no shipped
// signature declares must say so in its "Where it stops today" line, so it
// does not read as covered today.
func TestUseCasesNameUncoveredSurfaces(t *testing.T) {
	schemaDoc, err := readJSON[map[string]any](filepath.Join(repoRoot, filepath.FromSlash(schemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	props, _ := schemaDoc["properties"].(map[string]any)
	surfaces, _ := props["surface_types"].(map[string]any)
	items, _ := surfaces["items"].(map[string]any)
	enum, _ := items["enum"].([]any)
	if len(enum) == 0 {
		t.Fatal("schema has no surface_types enum")
	}

	sigs, errs := loadSignatures(repoRoot)
	if len(errs) > 0 {
		t.Fatalf("load signatures: %v", errs)
	}
	declared := map[string]bool{}
	for _, s := range sigs {
		doc, _ := s.raw.(map[string]any)
		list, _ := doc["surface_types"].([]any)
		for _, v := range list {
			if st, ok := v.(string); ok {
				declared[st] = true
			}
		}
	}

	b, err := os.ReadFile(filepath.Join(repoRoot, "docs", "use-cases.md"))
	if err != nil {
		t.Fatal(err)
	}
	useCases := strings.Split(string(b), "\n## ")[1:]
	if len(useCases) == 0 {
		t.Fatal(`docs/use-cases.md has no "## " use case sections`)
	}

	checked := 0
	for _, useCase := range useCases {
		title, _, _ := strings.Cut(useCase, "\n")
		var prose, stops []string
		for _, line := range strings.Split(useCase, "\n") {
			if strings.HasPrefix(line, "Where it stops today:") {
				stops = append(stops, strings.ToLower(line))
			} else {
				prose = append(prose, strings.ToLower(line))
			}
		}
		body := strings.Join(prose, "\n")
		stop := strings.Join(stops, "\n")
		for _, v := range enum {
			st, _ := v.(string)
			if st == "" || declared[st] {
				continue
			}
			phrase := strings.ReplaceAll(st, "_", " ")
			if !strings.Contains(body, phrase) {
				continue
			}
			checked++
			if !strings.Contains(stop, phrase) && !strings.Contains(stop, "`"+st+"`") {
				t.Errorf("use case %q names %q, which no shipped signature declares as a surface type; its \"Where it stops today\" line must say so", title, phrase)
			}
		}
	}
	t.Logf("%d uncovered surface mention(s) checked", checked)
}

// captureRecord is docs/captures/validate.json as the capture tool writes it.
type captureRecord struct {
	Command            string   `json:"command"`
	Directory          string   `json:"directory"`
	Version            string   `json:"version"`
	Commit             string   `json:"commit"`
	ChangedSinceCommit []string `json:"changedSinceCommit"`
	Fixture            string   `json:"fixture"`
	Date               string   `json:"date"`
	ExitCode           *int     `json:"exitCode"`
	Output             string   `json:"output"`
	Excerpt            [][2]int `json:"excerpt"`
}

const recapture = "re-capture with: cd tests/validate && go run -mod=vendor ./capture"

func readCaptureRecord(t *testing.T) captureRecord {
	t.Helper()
	rec, err := readJSON[captureRecord](filepath.Join(repoRoot, "docs", "captures", "validate.json"))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// The README's Validating section shows an excerpt of a recorded validator
// run. The excerpt must be the recorded output trimmed in place, its caption
// must name the command and link the full output, and the recorded output
// must match a fresh run, so a change to the output means a re-capture.
func TestReadmeValidatingCapture(t *testing.T) {
	rec := readCaptureRecord(t)
	if rec.Command != "go run -mod=vendor ." || rec.Directory != "tests/validate" {
		t.Errorf("record names command %q in %q, want %q in %q", rec.Command, rec.Directory, "go run -mod=vendor .", "tests/validate")
	}
	if rec.Version == "" || rec.Commit == "" || rec.Fixture == "" {
		t.Errorf("record has an empty version, commit or fixture: %+v", rec)
	}
	if _, err := time.Parse(time.RFC3339, rec.Date); err != nil {
		t.Errorf("record date %q: %v", rec.Date, err)
	}
	if rec.ExitCode == nil || *rec.ExitCode != 0 {
		t.Errorf("record exitCode must be 0, the README shows a passing run")
	}
	if len(rec.Excerpt) == 0 {
		t.Fatal("record has no excerpt ranges")
	}

	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rec.Output)))
	if err != nil {
		t.Fatal(err)
	}
	captured := string(b)
	lines := strings.Split(strings.TrimSuffix(captured, "\n"), "\n")
	var excerpt []string
	trimmed := false
	next := 1
	for _, r := range rec.Excerpt {
		if r[0] < next || r[1] < r[0] || r[1] > len(lines) {
			t.Fatalf("excerpt range %v is out of order or outside the %d recorded lines", r, len(lines))
		}
		if r[0] > next {
			excerpt = append(excerpt, "...")
			trimmed = true
		}
		excerpt = append(excerpt, lines[r[0]-1:r[1]]...)
		next = r[1] + 1
	}
	if next <= len(lines) {
		excerpt = append(excerpt, "...")
		trimmed = true
	}
	caption := "What `" + rec.Command + "` prints"
	if trimmed {
		caption += ", trimmed"
	}
	caption += " ([full output](" + rec.Output + ")):"

	rb, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(rb)
	start := strings.Index(readme, "\n## Validating\n")
	if start < 0 {
		t.Fatal(`README has no "## Validating" section`)
	}
	section := readme[start+len("\n## Validating\n"):]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	if !strings.Contains(section, "\n"+rec.Command+"\n") {
		t.Errorf("the Validating section does not list the recorded command %q", rec.Command)
	}
	want := caption + "\n\n```\n" + strings.Join(excerpt, "\n") + "\n```\n"
	if !strings.Contains(section, want) {
		t.Errorf("the Validating section does not show the recorded excerpt under its caption; want:\n%s\n%s", want, recapture)
	}

	var out bytes.Buffer
	run(repoRoot, false, &out)
	if strings.Contains(out.String(), "check 11b skipped") {
		t.Skip("git history unavailable here; the recorded output was not compared with a fresh run")
	}
	if out.String() != captured {
		t.Errorf("%s differs from a fresh validator run; %s\nfresh run:\n%s", rec.Output, recapture, out.String())
	}
}

// The record names a revision a reader can check out. The recorded version
// must resolve to a commit here, that commit must be the recorded one, and
// it must be reachable from origin/main: a commit made on a pull-request
// branch is not reachable from main after the squash merge, so a clone of
// main does not contain it.
func TestReadmeValidatingCaptureRevisionIsOnMain(t *testing.T) {
	rec := readCaptureRecord(t)
	gitOut := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", repoRoot}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(stdout.String()), nil
	}
	shallow, err := gitOut("rev-parse", "--is-shallow-repository")
	if err != nil {
		t.Skipf("git history unavailable here; the recorded revision was not resolved: %v", err)
	}
	if shallow == "true" {
		t.Skip("shallow clone; the recorded revision was not resolved")
	}

	got, err := gitOut("rev-parse", "--verify", "--quiet", rec.Version+"^{commit}")
	if err != nil {
		t.Fatalf("record version %q does not resolve to a commit here (%v); %s", rec.Version, err, recapture)
	}
	if rec.Commit != got {
		t.Errorf("record commit %q, want %s, the commit that version %q names; %s", rec.Commit, got, rec.Version, recapture)
	}
	if _, err := gitOut("rev-parse", "--verify", "--quiet", "origin/main^{commit}"); err != nil {
		t.Logf("origin/main unavailable here; whether the recorded commit is reachable from main was not checked: %v", err)
		return
	}
	if _, err := gitOut("merge-base", "--is-ancestor", got, "origin/main"); err != nil {
		t.Errorf("record version %q names %s, which is not reachable from origin/main, so a clone of main does not contain it; %s", rec.Version, got, recapture)
	}
}

// The capture record names the merge base because a commit made on a
// pull-request branch is not reachable from main after the squash merge, so
// a clone of main does not contain it. The merge does not delete a pushed
// pull-request commit: GitHub keeps it under refs/pull/<n>/head. The text
// that explains the record must give the first reason and must not say the
// merge removed the commit from the repository.
func TestCaptureTextSaysBranchCommitsAreNotReachableFromMain(t *testing.T) {
	// This file is scanned too; the pattern's source does not match itself.
	removed := regexp.MustCompile(`(?i)(?:not|still) in the repository after (?:the|a) (?:squash )?merge|squash merge (?:leaves|left) out`)
	for _, rel := range []string{"docs/validating.md", "CHANGELOG.md", "tests/validate/capture/main.go", "tests/validate/capture/main_test.go", "tests/validate/main_test.go"} {
		b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		// Go comments wrap, so the text is matched with comment markers
		// and line breaks folded into single spaces.
		text := strings.Join(strings.Fields(strings.ReplaceAll(string(b), "//", " ")), " ")
		for _, m := range removed.FindAllString(text, -1) {
			t.Errorf("%s says %q; a squash merge does not delete a pushed pull-request commit, say that the commit is not reachable from main, so a clone of main does not contain it", rel, m)
		}
	}
	b, err := os.ReadFile(filepath.Join(repoRoot, "docs", "validating.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"not reachable from main", "a clone of main does not contain it"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("docs/validating.md must say why the record names the merge base; it does not say %q", want)
		}
	}
}

func mustLoad(t *testing.T, rel string) map[string]any {
	t.Helper()
	ls, err := loadSignatureFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := ls.raw.(map[string]any)
	if !ok {
		t.Fatalf("%s: not an object", rel)
	}
	return m
}

func clone(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

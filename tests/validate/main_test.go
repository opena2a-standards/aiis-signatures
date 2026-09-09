package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

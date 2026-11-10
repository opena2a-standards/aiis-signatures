package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// Every failure message in this file carries signature ids, case names,
// operator names, counts and booleans only. No test prints a fixture case or
// a mutant.

var summaryLine = regexp.MustCompile(`^summary: (\d+) signatures, (\d+) mutants, (\d+) evade, (\d+) defence mutants fire$`)

// Label preservation is tested, not assumed: every operator, applied to every
// fixture case, is undone byte for byte by its inverse.
func TestMutateInverseRestoresEveryFixtureCase(t *testing.T) {
	sigs, _, problems := loadBench(repoRoot)
	if len(problems) > 0 {
		t.Fatalf("%d load problem(s); go run -mod=vendor . names them", len(problems))
	}
	ops := benchOperators()
	if len(ops) != 3 {
		t.Fatalf("%d operators, want 3", len(ops))
	}
	texts := 0
	for _, s := range sigs {
		for _, side := range benchSides(s) {
			for _, c := range side.cases {
				texts++
				for _, op := range ops {
					if op.inverse(op.apply(c.text)) != c.text {
						t.Errorf("%s/%s (%s) %s: inverse(op(text)) is not byte-identical to the case text", s.id, c.name, side.name, op.name)
					}
				}
			}
		}
	}
	if len(sigs) == 0 || texts == 0 {
		t.Fatalf("%d signatures and %d case texts loaded; the fixtures did not load", len(sigs), texts)
	}
	if !t.Failed() {
		t.Logf("%d signatures, %d case texts, %d operators: every inverse restored the case byte for byte", len(sigs), texts, len(ops))
	}
}

// The bench run on one fixture ends with the summary line, names the
// reference matcher and the production engine it does not measure, writes a
// counts file that agrees with the summary, and prints no case or mutant.
func TestMutateBenchOnOneFixturePrintsTheSummaryLine(t *testing.T) {
	const id = "AIIS-ATTR-IGNORE-INST-01"
	countsPath := filepath.Join(t.TempDir(), "mutate-counts.json")
	var out bytes.Buffer
	code := runMutate(benchOptions{root: repoRoot, only: []string{id}, operators: benchOperators(), countsPath: countsPath}, &out)
	if code != 0 {
		t.Errorf("bench exit %d, want 0", code)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	m := summaryLine.FindStringSubmatch(lines[len(lines)-1])
	if m == nil {
		t.Fatalf("the last of %d output lines is not the summary line", len(lines))
	}
	if m[1] != "1" {
		t.Errorf("summary counts %s signatures, want 1", m[1])
	}
	for _, want := range []string{
		"reference matcher: " + referenceMatcherPath,
		"production engine: " + productionEnginePath + " is not measured here",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("header does not carry %q", want)
		}
	}
	rows := 0
	for _, l := range lines {
		if strings.HasPrefix(l, id+" ") {
			rows++
		}
	}
	if rows != 1 {
		t.Errorf("%d table rows for %s, want 1", rows, id)
	}

	b, err := os.ReadFile(countsPath)
	if err != nil {
		t.Fatalf("counts file: %v", err)
	}
	var res benchResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("counts file is not JSON: %v", err)
	}
	for i, got := range []int{res.Summary.Signatures, res.Summary.Mutants, res.Summary.Evade, res.Summary.DefenceMutantsFire} {
		if strconv.Itoa(got) != m[i+1] {
			t.Errorf("counts file summary field %d is %d, the summary line says %s", i, got, m[i+1])
		}
	}
	if res.ReferenceMatcher != referenceMatcherPath || res.ProductionEngineMeasured {
		t.Errorf("counts file names matcher %q, production engine measured %t", res.ReferenceMatcher, res.ProductionEngineMeasured)
	}
	assertNoCaseText(t, "bench output", out.String())
	assertNoCaseText(t, "counts file", string(b))
}

// assertNoCaseText fails when s carries a non-ASCII code point (every mutant
// does) or the text of a fixture case long enough not to occur by chance.
func assertNoCaseText(t *testing.T, label, s string) {
	t.Helper()
	for i, r := range s {
		if r > unicode.MaxASCII {
			t.Errorf("%s carries a non-ASCII code point at byte %d", label, i)
			break
		}
	}
	sigs, _, _ := loadBench(repoRoot)
	for _, sg := range sigs {
		for _, side := range benchSides(sg) {
			for _, c := range side.cases {
				if len(c.text) >= 12 && strings.Contains(s, c.text) {
					t.Errorf("%s carries the text of case %s/%s", label, sg.id, c.name)
				}
			}
		}
	}
}

// writeBenchRoot lays out a repository root holding one signature and its
// fixture, for the bench to run on synthetic text.
func writeBenchRoot(t *testing.T, id, matchYAML string, fx Fixture) string {
	t.Helper()
	root := t.TempDir()
	sigDir := filepath.Join(root, signaturesDir, "test")
	fxDir := filepath.Join(root, filepath.FromSlash(fixturesDir))
	for _, d := range []string{sigDir, fxDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sigDir, id+".yaml"), []byte("id: "+id+"\nmatch:\n"+matchYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(fx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fxDir, id+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// An operator that writes a code point inside the signature's own
// unicode_range is not applied to it: the cell reads n/a and adds no mutant.
func TestMutateOperatorInsideTheSignaturesRangeReadsNA(t *testing.T) {
	const id = "AIIS-TEST-ZERO-WIDTH-RUN-01"
	root := writeBenchRoot(t, id, "  type: unicode_range\n  ranges:\n    - { from: \"\\u200B\", to: \"\\u200D\" }\n", Fixture{
		Signature:      id,
		ShouldMatch:    []FixtureCase{{Name: "zero-width-run", Text: "s\u200bt\u200bo\u200bp"}},
		ShouldNotMatch: []FixtureCase{{Name: "plain-words", Text: "plain words"}},
	})
	opts := benchOptions{root: root, operators: benchOperators()}
	res := measureBench(opts)
	if len(res.Signatures) != 1 {
		t.Fatalf("%d rows, want 1", len(res.Signatures))
	}
	row := res.Signatures[0]
	for _, oc := range row.Operators {
		if want := oc.Operator != "zero-width"; oc.Applied != want {
			t.Errorf("%s applied %t, want %t", oc.Operator, oc.Applied, want)
		}
		if !oc.Applied && (oc.Mutants+oc.Unchanged+oc.DefenceMutants+oc.DefenceUnchanged+oc.Defects) != 0 {
			t.Errorf("%s is n/a but counted", oc.Operator)
		}
	}
	if row.Mutants != 2 || row.Evade != 0 || row.DefenceMutants != 2 || row.DefenceFire != 0 || res.Summary.NotApplied != 1 {
		t.Errorf("row mutants %d evade %d defence mutants %d fire %d, not applied %d; want 2 0 2 0 1",
			row.Mutants, row.Evade, row.DefenceMutants, row.DefenceFire, res.Summary.NotApplied)
	}
	var out bytes.Buffer
	if code := runMutate(opts, &out); code != 0 {
		t.Errorf("bench exit %d, want 0", code)
	}
	if !regexp.MustCompile(`(?m)^` + id + ` .* n/a `).MatchString(out.String()) {
		t.Errorf("the row for %s has no n/a cell", id)
	}
}

func TestOperatorAppliesReadsNestedRanges(t *testing.T) {
	ranged := func(from, to string) MatchSpec {
		return MatchSpec{Type: "unicode_range", Ranges: []UnicodeRange{{From: from, To: to}}}
	}
	for _, tc := range []struct {
		name       string
		spec       MatchSpec
		notApplied string
	}{
		{"zero width space inside", ranged("\u200b", "\u200f"), "zero-width"},
		{"fullwidth forms inside", ranged("\uff00", "\uffef"), "fullwidth"},
		{"cyrillic inside composite", MatchSpec{Type: "composite", AnyOf: []MatchSpec{
			{Type: "regex", Pattern: "x"}, ranged("\u0400", "\u04ff"),
		}}, "confusables"},
		{"greek inside all_of", MatchSpec{Type: "composite", AllOf: []MatchSpec{ranged("\u0370", "\u03ff")}}, "confusables"},
		{"tag block", ranged("\U000E0000", "\U000E007F"), ""},
		{"regex only", MatchSpec{Type: "regex", Pattern: "x"}, ""},
	} {
		for _, op := range benchOperators() {
			if got, want := operatorApplies(op, tc.spec), op.name != tc.notApplied; got != want {
				t.Errorf("%s: %s applies %t, want %t", tc.name, op.name, got, want)
			}
		}
	}
}

// A mutant whose inverse does not restore its case is a bench defect: it is
// counted neither as an evasion nor as a match, and the run exits non-zero
// while the summary stays the last line.
func TestMutateInverseFailureIsADefectNotAnEvasion(t *testing.T) {
	const id = "AIIS-TEST-PLAIN-WORD-01"
	root := writeBenchRoot(t, id, "  type: substring\n  contains: [\"stop\"]\n", Fixture{
		Signature:      id,
		ShouldMatch:    []FixtureCase{{Name: "word", Text: "please stop now"}},
		ShouldNotMatch: []FixtureCase{{Name: "other-word", Text: "please go on"}},
	})
	lossy := operator{
		name:    "lossy",
		apply:   func(s string) string { return strings.ReplaceAll(s, "stop", "st0p") },
		inverse: func(s string) string { return s },
	}
	opts := benchOptions{root: root, operators: []operator{lossy}}
	res := measureBench(opts)
	if res.Summary.Defects != 1 || res.Summary.Evade != 0 || res.Summary.Mutants != 0 {
		t.Errorf("defects %d evade %d mutants %d, want 1 0 0", res.Summary.Defects, res.Summary.Evade, res.Summary.Mutants)
	}
	if len(res.Defects) != 1 || res.Defects[0].Case != "word" || res.Defects[0].Operator != "lossy" {
		t.Errorf("defects %+v, want one for case word, operator lossy", res.Defects)
	}
	var out bytes.Buffer
	if code := runMutate(opts, &out); code == 0 {
		t.Error("bench exit 0 with a defect, want non-zero")
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if !summaryLine.MatchString(lines[len(lines)-1]) {
		t.Error("the summary is not the last line after a defect")
	}
	if !strings.Contains(out.String(), "DEFECT "+id+"/word (shouldMatch) lossy") {
		t.Error("no DEFECT line names the signature, case and operator")
	}
}

// A signature id outside the id grammar is not used to name a fixture path:
// the signature is not benched, the run names it and exits non-zero.
func TestMutateIdOutsideTheGrammarIsNotBenched(t *testing.T) {
	root := t.TempDir()
	sigDir := filepath.Join(root, signaturesDir, "test")
	if err := os.MkdirAll(sigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "id: ../../outside\nmatch:\n  type: substring\n  contains: [\"stop\"]\n"
	if err := os.WriteFile(filepath.Join(sigDir, "outside.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Fixture{
		Signature:      "../../outside",
		ShouldMatch:    []FixtureCase{{Name: "word", Text: "please stop now"}},
		ShouldNotMatch: []FixtureCase{{Name: "other-word", Text: "please go on"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The file the id would name if it were joined onto tests/fixtures.
	if err := os.WriteFile(filepath.Join(root, "outside.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	opts := benchOptions{root: root, operators: benchOperators()}
	res := measureBench(opts)
	if len(res.Signatures) != 0 {
		t.Errorf("%d rows, want 0", len(res.Signatures))
	}
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "does not match the id grammar") {
		t.Errorf("%d problem(s), want one naming the id grammar", len(res.Problems))
	}
	var out bytes.Buffer
	if code := runMutate(opts, &out); code == 0 {
		t.Error("bench exit 0 with an id outside the grammar, want non-zero")
	}
}

// Evasions and defence mutants that fire are findings the bench reports; they
// never fail the run.
func TestMutateFindingsNeverFailTheRun(t *testing.T) {
	for _, tc := range []struct {
		name, id, match string
		fx              Fixture
		evade, fire     int
		firing          []string
	}{
		{
			name: "substring evaded", id: "AIIS-TEST-PLAIN-WORD-01", match: "  type: substring\n  contains: [\"stop\"]\n",
			fx: Fixture{
				ShouldMatch:    []FixtureCase{{Name: "word", Text: "please stop now"}},
				ShouldNotMatch: []FixtureCase{{Name: "other-word", Text: "please go on"}},
			},
			evade: 3, fire: 0, firing: []string{},
		},
		{
			name: "defence fires", id: "AIIS-TEST-CYRILLIC-01", match: "  type: regex\n  pattern: '\\p{Cyrillic}'\n",
			fx: Fixture{
				ShouldMatch:    []FixtureCase{{Name: "cyrillic-word", Text: "\u0436\u0438\u0437\u043d\u044c"}},
				ShouldNotMatch: []FixtureCase{{Name: "latin-words", Text: "plain words"}},
			},
			evade: 0, fire: 1, firing: []string{"confusables"},
		},
	} {
		tc.fx.Signature = tc.id
		root := writeBenchRoot(t, tc.id, tc.match, tc.fx)
		opts := benchOptions{root: root, operators: benchOperators()}
		res := measureBench(opts)
		if res.Summary.Evade != tc.evade || res.Summary.DefenceMutantsFire != tc.fire {
			t.Errorf("%s: evade %d fire %d, want %d %d", tc.name, res.Summary.Evade, res.Summary.DefenceMutantsFire, tc.evade, tc.fire)
		}
		if got := strings.Join(res.Signatures[0].FiringOperators, ","); got != strings.Join(tc.firing, ",") {
			t.Errorf("%s: firing operators %q, want %q", tc.name, got, strings.Join(tc.firing, ","))
		}
		var out bytes.Buffer
		if code := runMutate(opts, &out); code != 0 {
			t.Errorf("%s: bench exit %d, want 0", tc.name, code)
		}
	}
}

func TestZeroWidthInterleave(t *testing.T) {
	if got, want := zeroWidthInterleave("Ab 1-c\u00e9"), "A\u200bb\u200b 1-c\u200b\u00e9\u200b"; got != want {
		t.Errorf("interleave: got %+q, want %+q", got, want)
	}
	if got, want := zeroWidthRemove("a\u200bb\u200cc\u200dd\u2060e"), "abcde"; got != want {
		t.Errorf("remove: got %+q, want %+q", got, want)
	}
	if got, want := zeroWidthInterleave("1 2\n"), "1 2\n"; got != want {
		t.Errorf("no letters: got %+q, want %+q", got, want)
	}
}

func TestFullwidth(t *testing.T) {
	if got, want := toFullwidth("!~ Az\n\u00e9"), "\uff01\uff5e \uff21\uff5a\n\u00e9"; got != want {
		t.Errorf("to: got %+q, want %+q", got, want)
	}
	if got, want := fromFullwidth("\uff01\uff5e \uff21\uff5a\n\u00e9"), "!~ Az\n\u00e9"; got != want {
		t.Errorf("from: got %+q, want %+q", got, want)
	}
}

// The confusables table is one to one, from an ASCII Latin letter to a
// Cyrillic or Greek letter of the same case, so its reverse is exact.
func TestConfusablesTable(t *testing.T) {
	seen := map[rune]bool{}
	for _, p := range confusablePairs {
		if !(p.latin >= 'A' && p.latin <= 'Z' || p.latin >= 'a' && p.latin <= 'z') {
			t.Errorf("U+%04X is not an ASCII Latin letter", p.latin)
		}
		if !unicode.Is(unicode.Cyrillic, p.lookalike) && !unicode.Is(unicode.Greek, p.lookalike) {
			t.Errorf("U+%04X is neither Cyrillic nor Greek", p.lookalike)
		}
		if unicode.IsUpper(p.latin) != unicode.IsUpper(p.lookalike) || !unicode.IsLetter(p.lookalike) {
			t.Errorf("U+%04X and U+%04X differ in letter case", p.latin, p.lookalike)
		}
		if seen[p.latin] || seen[p.lookalike] {
			t.Errorf("U+%04X or U+%04X appears twice", p.latin, p.lookalike)
		}
		seen[p.latin], seen[p.lookalike] = true, true
	}
	if len(confusableTo) != len(confusablePairs) || len(confusableFrom) != len(confusablePairs) {
		t.Errorf("table %d pairs, forward %d, reverse %d", len(confusablePairs), len(confusableTo), len(confusableFrom))
	}
	if got, want := toConfusables("Ace, by Zt"), "\u0410\u0441\u0435, b\u0443 \u0396t"; got != want {
		t.Errorf("to: got %+q, want %+q", got, want)
	}
	if got, want := fromConfusables("\u0410\u0441\u0435, b\u0443 \u0396t"), "Ace, by Zt"; got != want {
		t.Errorf("from: got %+q, want %+q", got, want)
	}
}

// Bytes that are not valid UTF-8 pass through every operator and its inverse
// unchanged.
func TestOperatorsKeepInvalidUTF8Bytes(t *testing.T) {
	in := "a\xffb\xc3"
	for _, op := range benchOperators() {
		if got := op.inverse(op.apply(in)); got != in {
			t.Errorf("%s: invalid bytes not restored: got %+q", op.name, got)
		}
	}
}

// rowTally is the countable part of a row.
type rowTally struct {
	mutants, unchanged, matched, evade, defMutants, defUnchanged, defFire int
}

func tallyOf(r sigCounts) rowTally {
	return rowTally{r.Mutants, r.Unchanged, r.Matched, r.Evade, r.DefenceMutants, r.DefenceUnchanged, r.DefenceFire}
}

// The hand check: every row of the bench is recounted with a compile of its
// own of each signature's match block and calls of its own of the matcher,
// and the counts must agree. With -v it logs, by case name, whether each
// transform changed the case and whether the matcher fires on the result,
// for three rows: the first that evades; the first with a mutant the matcher
// still fires on (when no row has one, the first whose transforms all left
// its cases unchanged); and the first other row with a defence mutant that
// fires (when none fires, the first other row with defence mutants).
func TestMutateHandCheck(t *testing.T) {
	sigs, _, problems := loadBench(repoRoot)
	if len(problems) > 0 {
		t.Fatalf("%d load problem(s)", len(problems))
	}
	ops := benchOperators()
	res := measureBench(benchOptions{root: repoRoot, operators: ops})
	if res.Summary.BaselineMismatches+res.Summary.Defects > 0 {
		t.Fatalf("%d baseline mismatch(es) and %d defect(s); the recount assumes none", res.Summary.BaselineMismatches, res.Summary.Defects)
	}
	if len(sigs) != len(res.Signatures) {
		t.Fatalf("%d signatures loaded, %d bench rows", len(sigs), len(res.Signatures))
	}

	chosen := map[string]string{} // signature id -> role
	pick := func(role string, ok func(sigCounts) bool) bool {
		for _, r := range res.Signatures {
			if _, taken := chosen[r.Signature]; !taken && ok(r) {
				chosen[r.Signature] = role
				return true
			}
		}
		return false
	}
	pick("evading", func(r sigCounts) bool { return r.Evade > 0 })
	if !pick("matched", func(r sigCounts) bool { return r.Matched > 0 }) {
		pick("matched (no row has a matched mutant; every transform of this row left its case unchanged)",
			func(r sigCounts) bool { return r.Mutants == 0 && r.Unchanged > 0 })
	}
	if !pick("defence", func(r sigCounts) bool { return r.DefenceFire > 0 }) {
		pick("defence (no defence mutant fires in any row)", func(r sigCounts) bool { return r.DefenceMutants > 0 })
	}
	if len(chosen) != 3 {
		t.Errorf("%d rows chosen for the hand check, want 3", len(chosen))
	}

	rows := map[string]sigCounts{}
	for _, r := range res.Signatures {
		rows[r.Signature] = r
	}
	for _, s := range sigs {
		m, err := compileMatch(s.spec) // a compile of its own, not the bench's matcher
		if err != nil {
			t.Fatalf("%s: match block: %v", s.id, err)
		}
		role, logged := chosen[s.id]
		if logged {
			t.Logf("row %s: %s", role, s.id)
		}
		var got rowTally
		for _, side := range benchSides(s) {
			for _, c := range side.cases {
				for _, op := range ops {
					if !operatorApplies(op, s.spec) {
						continue
					}
					mutant := op.apply(c.text)
					unchanged := mutant == c.text
					fires := m.Match(mutant)
					if logged {
						t.Logf("  %s/%s (%s) %s: unchanged=%t matched=%t", s.id, c.name, side.name, op.name, unchanged, fires)
					}
					switch {
					case unchanged && side.defence:
						got.defUnchanged++
					case unchanged:
						got.unchanged++
					case side.defence:
						got.defMutants++
						if fires {
							got.defFire++
						}
					case fires:
						got.mutants++
						got.matched++
					default:
						got.mutants++
						got.evade++
					}
				}
			}
		}
		want := tallyOf(rows[s.id])
		if got != want {
			t.Errorf("%s: recount %+v, bench row %+v", s.id, got, want)
		}
		if logged {
			t.Logf("  recount %+v; bench row agrees: %t", got, got == want)
		}
	}
}

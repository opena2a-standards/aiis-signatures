package main

// The evasion bench, run with -mutate. For every signature with a fixture it
// applies each operator of mutate_operators.go to every shouldMatch and
// shouldNotMatch case, runs the reference matcher of matcher.go on each
// mutant, and prints one row of counts per signature: how many mutants the
// matcher still fires on, how many evade it, and how many defence mutants it
// starts to fire on.
//
// The bench reports and never fails on what it measures: an evading mutant or
// a defence mutant that fires is a finding, not an error. The exit code is
// non-zero only for a bench defect (a mutant whose inverse does not restore
// its case), a case whose unmutated text disagrees with its label, or a
// signature or fixture that does not load. It edits no signature or fixture.
//
// No output carries a case text or a mutant: the table, the problem lines and
// the counts file hold signature ids, case names, operator names, counts and
// booleans only. Mutants are rebuilt by running the bench.

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

const (
	mutateCountsPath     = "tests/validate/testdata/mutate-counts.json"
	referenceMatcherPath = "tests/validate/matcher.go"
	productionEnginePath = "honeymap/internal/classify/aiis/aiis.go"
)

// matcherSource is the matcher compiled into this binary. Its sha256 names
// the reference matcher in the table header and the counts file.
//
//go:embed matcher.go
var matcherSource []byte

type benchCase struct {
	name string
	text string
}

// benchSignature is one signature with its fixture cases resolved to text.
type benchSignature struct {
	id      string
	spec    MatchSpec
	matcher Matcher
	match   []benchCase // shouldMatch
	noMatch []benchCase // shouldNotMatch
}

// benchSide is one half of a fixture. A defence side holds the
// shouldNotMatch cases, whose mutants must not fire.
type benchSide struct {
	name    string
	cases   []benchCase
	defence bool
}

func benchSides(s benchSignature) []benchSide {
	return []benchSide{
		{name: "shouldMatch", cases: s.match},
		{name: "shouldNotMatch", cases: s.noMatch, defence: true},
	}
}

type benchOptions struct {
	root       string
	only       []string // signature ids to bench; empty benches every signature with a fixture
	operators  []operator
	countsPath string // where the counts file goes; empty writes none
}

// opCounts is one operator's cell of a row.
type opCounts struct {
	Operator         string `json:"operator"`
	Applied          bool   `json:"applied"`
	Mutants          int    `json:"mutants"`
	Unchanged        int    `json:"unchanged"`
	Matched          int    `json:"matched"`
	Evade            int    `json:"evade"`
	DefenceMutants   int    `json:"defenceMutants"`
	DefenceUnchanged int    `json:"defenceUnchanged"`
	DefenceFire      int    `json:"defenceFire"`
	Defects          int    `json:"defects"`
}

// sigCounts is one row of the table.
type sigCounts struct {
	Signature        string     `json:"signature"`
	Cases            int        `json:"cases"`
	Mutants          int        `json:"mutants"`
	Unchanged        int        `json:"unchanged"`
	Matched          int        `json:"matched"`
	Evade            int        `json:"evade"`
	EvadingOperators []string   `json:"evadingOperators"`
	DefenceCases     int        `json:"defenceCases"`
	DefenceMutants   int        `json:"defenceMutants"`
	DefenceUnchanged int        `json:"defenceUnchanged"`
	DefenceFire      int        `json:"defenceFire"`
	FiringOperators  []string   `json:"firingOperators"`
	Operators        []opCounts `json:"operators"`
}

// benchIssue names a case the bench could not count, by name only.
type benchIssue struct {
	Signature string `json:"signature"`
	Side      string `json:"side"`
	Case      string `json:"case"`
	Operator  string `json:"operator,omitempty"`
}

type benchSummary struct {
	Signatures         int `json:"signatures"`
	Cases              int `json:"cases"`
	Mutants            int `json:"mutants"`
	Unchanged          int `json:"unchanged"`
	Matched            int `json:"matched"`
	Evade              int `json:"evade"`
	DefenceCases       int `json:"defenceCases"`
	DefenceMutants     int `json:"defenceMutants"`
	DefenceUnchanged   int `json:"defenceUnchanged"`
	DefenceMutantsFire int `json:"defenceMutantsFire"`
	NotApplied         int `json:"notApplied"`
	BaselineMismatches int `json:"baselineMismatches"`
	Defects            int `json:"defects"`
}

// benchResult is everything the bench measured; it is also the counts file.
type benchResult struct {
	ReferenceMatcher         string       `json:"referenceMatcher"`
	ReferenceMatcherSha256   string       `json:"referenceMatcherSha256"`
	ProductionEngine         string       `json:"productionEngine"`
	ProductionEngineMeasured bool         `json:"productionEngineMeasured"`
	Operators                []string     `json:"operators"`
	Signatures               []sigCounts  `json:"signatures"`
	NotBenched               []string     `json:"notBenched"`
	Problems                 []string     `json:"problems"`
	BaselineMismatches       []benchIssue `json:"baselineMismatches"`
	Defects                  []benchIssue `json:"defects"`
	Summary                  benchSummary `json:"summary"`
}

// loadBench pairs every signature that loads and has a fixture with its
// cases resolved to text, sorted by id. notBenched names the signatures
// without a fixture; problems names what did not load. Neither carries case
// text: the checks of go run -mod=vendor . give the detail.
func loadBench(root string) (sigs []benchSignature, notBenched, problems []string) {
	loaded, errs := loadSignatures(root)
	problems = append(problems, errs...)
	for _, ls := range loaded {
		id := ls.sig.ID
		// The id names the fixture file; one outside the grammar could name a
		// path outside tests/fixtures.
		if !idGrammar.MatchString(id) {
			problems = append(problems, fmt.Sprintf("%s: id %q does not match the id grammar; not benched", ls.path, id))
			continue
		}
		if ls.matcher == nil {
			problems = append(problems, fmt.Sprintf("%s: match block does not compile", id))
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(fixturesDir), id+".json")
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			notBenched = append(notBenched, id)
			continue
		}
		fx, err := readJSON[Fixture](p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: fixture does not load", id))
			continue
		}
		bs := benchSignature{id: id, spec: ls.sig.Match, matcher: ls.matcher}
		resolved := true
		for _, side := range []struct {
			in  []FixtureCase
			out *[]benchCase
		}{{fx.ShouldMatch, &bs.match}, {fx.ShouldNotMatch, &bs.noMatch}} {
			for _, c := range side.in {
				text, err := caseText(c)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s/%s: codepoints do not resolve", id, c.Name))
					resolved = false
					continue
				}
				*side.out = append(*side.out, benchCase{name: c.Name, text: text})
			}
		}
		if resolved {
			sigs = append(sigs, bs)
		}
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].id < sigs[j].id })
	sort.Strings(notBenched)
	return sigs, notBenched, problems
}

// signatureRanges collects the unicode_range ranges of spec at any depth of a
// composite.
func signatureRanges(spec MatchSpec) [][2]rune {
	var out [][2]rune
	if spec.Type == "unicode_range" {
		for _, r := range spec.Ranges {
			from, to := []rune(r.From), []rune(r.To)
			if len(from) == 1 && len(to) == 1 {
				out = append(out, [2]rune{from[0], to[0]})
			}
		}
	}
	for _, sub := range spec.AllOf {
		out = append(out, signatureRanges(sub)...)
	}
	for _, sub := range spec.AnyOf {
		out = append(out, signatureRanges(sub)...)
	}
	return out
}

// operatorApplies is false when op writes a code point inside one of the
// signature's own unicode_range ranges.
func operatorApplies(op operator, spec MatchSpec) bool {
	for _, sr := range signatureRanges(spec) {
		for _, e := range op.emits {
			if e[0] <= sr[1] && sr[0] <= e[1] {
				return false
			}
		}
	}
	return true
}

// measureBench runs every operator over every case and returns the counts.
func measureBench(opts benchOptions) benchResult {
	sigs, notBenched, problems := loadBench(opts.root)
	sum := sha256.Sum256(matcherSource)
	res := benchResult{
		ReferenceMatcher:       referenceMatcherPath,
		ReferenceMatcherSha256: hex.EncodeToString(sum[:]),
		ProductionEngine:       productionEnginePath,
		Operators:              []string{},
		Signatures:             []sigCounts{},
		NotBenched:             []string{},
		Problems:               append([]string{}, problems...),
		BaselineMismatches:     []benchIssue{},
		Defects:                []benchIssue{},
	}
	for _, op := range opts.operators {
		res.Operators = append(res.Operators, op.name)
	}
	want := map[string]bool{}
	for _, id := range opts.only {
		want[id] = true
	}
	for _, id := range notBenched {
		if len(want) == 0 || want[id] {
			res.NotBenched = append(res.NotBenched, id)
		}
	}
	found := map[string]bool{}
	for _, s := range sigs {
		if len(want) > 0 && !want[s.id] {
			continue
		}
		found[s.id] = true
		res.Signatures = append(res.Signatures, benchSignatureRow(s, opts.operators, &res))
	}
	for _, id := range opts.only {
		if !found[id] && !contains(notBenched, id) {
			res.Problems = append(res.Problems, fmt.Sprintf("%s: no signature with a fixture has this id", id))
		}
	}
	sm := &res.Summary
	for _, row := range res.Signatures {
		sm.Signatures++
		sm.Cases += row.Cases
		sm.Mutants += row.Mutants
		sm.Unchanged += row.Unchanged
		sm.Matched += row.Matched
		sm.Evade += row.Evade
		sm.DefenceCases += row.DefenceCases
		sm.DefenceMutants += row.DefenceMutants
		sm.DefenceUnchanged += row.DefenceUnchanged
		sm.DefenceMutantsFire += row.DefenceFire
		for _, oc := range row.Operators {
			if !oc.Applied {
				sm.NotApplied++
			}
		}
	}
	sm.BaselineMismatches = len(res.BaselineMismatches)
	sm.Defects = len(res.Defects)
	return res
}

// benchSignatureRow measures one signature. Only a case whose unmutated text
// agrees with its label is mutated; a mutant is counted only when its
// inverse restores the case byte for byte and it differs from the case.
func benchSignatureRow(s benchSignature, ops []operator, res *benchResult) sigCounts {
	row := sigCounts{
		Signature:        s.id,
		Cases:            len(s.match),
		DefenceCases:     len(s.noMatch),
		EvadingOperators: []string{},
		FiringOperators:  []string{},
		Operators:        []opCounts{},
	}
	var sides []benchSide
	for _, side := range benchSides(s) {
		kept := benchSide{name: side.name, defence: side.defence}
		for _, c := range side.cases {
			if s.matcher.Match(c.text) == side.defence {
				res.BaselineMismatches = append(res.BaselineMismatches, benchIssue{Signature: s.id, Side: side.name, Case: c.name})
				continue
			}
			kept.cases = append(kept.cases, c)
		}
		sides = append(sides, kept)
	}
	for _, op := range ops {
		oc := opCounts{Operator: op.name, Applied: operatorApplies(op, s.spec)}
		if oc.Applied {
			for _, side := range sides {
				for _, c := range side.cases {
					mutant := op.apply(c.text)
					switch {
					case op.inverse(mutant) != c.text:
						oc.Defects++
						res.Defects = append(res.Defects, benchIssue{Signature: s.id, Side: side.name, Case: c.name, Operator: op.name})
					case mutant == c.text && side.defence:
						oc.DefenceUnchanged++
					case mutant == c.text:
						oc.Unchanged++
					case side.defence:
						oc.DefenceMutants++
						if s.matcher.Match(mutant) {
							oc.DefenceFire++
						}
					default:
						oc.Mutants++
						if s.matcher.Match(mutant) {
							oc.Matched++
						} else {
							oc.Evade++
						}
					}
				}
			}
		}
		row.Mutants += oc.Mutants
		row.Unchanged += oc.Unchanged
		row.Matched += oc.Matched
		row.Evade += oc.Evade
		row.DefenceMutants += oc.DefenceMutants
		row.DefenceUnchanged += oc.DefenceUnchanged
		row.DefenceFire += oc.DefenceFire
		if oc.Evade > 0 {
			row.EvadingOperators = append(row.EvadingOperators, op.name)
		}
		if oc.DefenceFire > 0 {
			row.FiringOperators = append(row.FiringOperators, op.name)
		}
		row.Operators = append(row.Operators, oc)
	}
	return row
}

// runMutate measures, prints the table, writes the counts file and returns
// the exit code. The summary line is always the last line.
func runMutate(opts benchOptions, out io.Writer) int {
	res := measureBench(opts)
	writeBenchTable(out, res, opts.operators)
	code := 0
	for _, p := range res.Problems {
		fmt.Fprintf(out, "PROBLEM %s\n", p)
		code = 1
	}
	for _, id := range res.NotBenched {
		fmt.Fprintf(out, "note: %s has no fixture and is not benched\n", id)
	}
	for _, b := range res.BaselineMismatches {
		fmt.Fprintf(out, "BASELINE %s/%s (%s): the unmutated case disagrees with its label; its mutants are not counted\n", b.Signature, b.Case, b.Side)
		code = 1
	}
	for _, d := range res.Defects {
		fmt.Fprintf(out, "DEFECT %s/%s (%s) %s: the inverse does not restore the case byte for byte; not counted\n", d.Signature, d.Case, d.Side, d.Operator)
		code = 1
	}
	if opts.countsPath != "" {
		if err := writeBenchCounts(opts.countsPath, res); err != nil {
			fmt.Fprintf(out, "PROBLEM counts file: %v\n", err)
			code = 1
		} else {
			label := opts.countsPath
			if rel, err := filepath.Rel(opts.root, opts.countsPath); err == nil && !strings.HasPrefix(rel, "..") {
				label = filepath.ToSlash(rel)
			}
			fmt.Fprintf(out, "counts: %s\n", label)
		}
	}
	fmt.Fprintf(out, "summary: %d signatures, %d mutants, %d evade, %d defence mutants fire\n",
		res.Summary.Signatures, res.Summary.Mutants, res.Summary.Evade, res.Summary.DefenceMutantsFire)
	return code
}

func writeBenchTable(out io.Writer, res benchResult, ops []operator) {
	fmt.Fprintln(out, "AIIS evasion bench: each fixture case under invertible, label-preserving transforms, run through the reference matcher")
	fmt.Fprintf(out, "reference matcher: %s (compileMatch), sha256 %s\n", res.ReferenceMatcher, res.ReferenceMatcherSha256)
	fmt.Fprintf(out, "production engine: %s is not measured here\n", res.ProductionEngine)
	var about []string
	for _, op := range ops {
		if op.about == "" {
			about = append(about, op.name)
			continue
		}
		about = append(about, op.name+" ("+op.about+")")
	}
	fmt.Fprintf(out, "operators: %s\n", strings.Join(about, "; "))
	fmt.Fprintln(out, "cases = shouldMatch cases; mutants = transforms that changed a case; matched = mutants the matcher still fires on; evade = mutants it misses")
	fmt.Fprintln(out, "<operator> = evade/mutants for that operator; n/a = not applied, the operator writes a code point inside the signature's own unicode_range")
	fmt.Fprintln(out, "def-* = the same for shouldNotMatch cases; def-fire = defence mutants the matcher fires on (false positives)")
	fmt.Fprintln(out, "unchanged = transforms that left a case byte-identical; they are not mutants and are not counted")
	fmt.Fprintln(out)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	head := []string{"signature", "cases", "mutants", "unchanged", "matched", "evade"}
	for _, op := range ops {
		head = append(head, op.name)
	}
	head = append(head, "evading-operators", "def-cases", "def-mutants", "def-unchanged", "def-fire", "firing-operators")
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	n := strconv.Itoa
	for _, row := range res.Signatures {
		cells := []string{row.Signature, n(row.Cases), n(row.Mutants), n(row.Unchanged), n(row.Matched), n(row.Evade)}
		for _, oc := range row.Operators {
			if !oc.Applied {
				cells = append(cells, "n/a")
				continue
			}
			cells = append(cells, n(oc.Evade)+"/"+n(oc.Mutants))
		}
		cells = append(cells, operatorList(row.EvadingOperators), n(row.DefenceCases), n(row.DefenceMutants),
			n(row.DefenceUnchanged), n(row.DefenceFire), operatorList(row.FiringOperators))
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
	fmt.Fprintln(out)
}

func operatorList(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

func writeBenchCounts(path string, res benchResult) error {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

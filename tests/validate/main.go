// Command aiis-validate is the gate for this corpus. It runs offline with
// vendored dependencies: `go run -mod=vendor .` from tests/validate.
//
// It loads every signature under signatures/, validates it against schema
// 0.2, cross-checks it against the family registry, the vendored Agent
// Threat Matrix snapshot, the canonical class list, the exposure class
// registry and the vendored HackMyAgent check id list, runs every fixture
// case through a real implementation of the four match types, checks the
// retired id list, and regenerates the technique crosswalk. Every check
// prints one ok or FAIL line; WARNING lines never fail the run.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const (
	schemaPath        = "schema/aiis-v0.2.schema.json"
	familiesPath      = "schema/families.json"
	exposurePath      = "schema/exposure-classes.json"
	matrixPath        = "vendor/agent-threat-matrix/matrix.json"
	canonicalPath     = "vendor/agent-threat-matrix/canonical-classes.json"
	matrixVendorPath  = "vendor/agent-threat-matrix/VENDOR.json"
	hmaCheckIDsPath   = "vendor/hackmyagent/check-ids.json"
	hmaVendorPath     = "vendor/hackmyagent/VENDOR.json"
	retiredPath       = "retired-ids.yaml"
	crosswalkPath     = "crosswalks/technique-signatures.json"
	signaturesDir     = "signatures"
	fixturesDir       = "tests/fixtures"
	minFixtureCases   = 3
	totalChecks       = 13
	retiredDateFormat = `^\d{4}-\d{2}-\d{2}$`
)

var (
	idGrammar           = regexp.MustCompile(`^AIIS-([A-Z]{3,12})-([A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*)-([0-9]{2})$`)
	retiredUnionGrammar = regexp.MustCompile(`^AIIS-(?:[0-9]{4}|[A-Z]{3,12}-[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-[0-9]{2})$`)
	techniqueGrammar    = regexp.MustCompile(`^T-\d{4}(\.\d{3})?$`)
	retiredDate         = regexp.MustCompile(retiredDateFormat)
	fortyHex            = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Signature is the subset of a signature file the cross-checks read. The
// schema check runs on the raw document, so unknown keys are caught there.
type Signature struct {
	SchemaVersion       string      `json:"schema_version"`
	ID                  string      `json:"id"`
	Category            string      `json:"category"`
	Status              string      `json:"status"`
	TechniqueID         string      `json:"technique_id"`
	RelatedTechniqueIDs []string    `json:"related_technique_ids"`
	AttackVector        string      `json:"attack_vector"`
	AttackClass         string      `json:"attack_class"`
	ExposureClass       string      `json:"exposure_class"`
	HMACheckIDs         []string    `json:"hma_check_ids"`
	Provenance          *Provenance `json:"provenance"`
	Match               MatchSpec   `json:"match"`
}

// Provenance is the evidence block behind an active signature.
type Provenance struct {
	EvidenceTier string `json:"evidence_tier"`
	Source       string `json:"source"`
	FirstSeen    string `json:"first_seen"`
}

type loadedSignature struct {
	path    string // relative to root, slash separated
	raw     any    // JSON compatible document for the schema check
	sig     Signature
	matcher Matcher
}

// Fixture is one tests/fixtures/<id>.json file.
type Fixture struct {
	Signature      string        `json:"signature"`
	Note           string        `json:"note"`
	Surface        string        `json:"surface"`
	Domain         string        `json:"domain"`
	ShouldMatch    []FixtureCase `json:"shouldMatch"`
	ShouldNotMatch []FixtureCase `json:"shouldNotMatch"`
}

// FixtureCase carries the document either as text or as hex codepoints.
type FixtureCase struct {
	Name       string   `json:"name"`
	Text       string   `json:"text"`
	Codepoints []string `json:"codepoints"`
}

type familiesFile struct {
	SchemaVersion string   `json:"schemaVersion"`
	TokenPattern  string   `json:"tokenPattern"`
	Families      []family `json:"families"`
}

type family struct {
	Token       string   `json:"token"`
	Category    string   `json:"category"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	MintedIn    string   `json:"mintedIn"`
	IDs         []string `json:"ids"`
}

type exposureFile struct {
	Classes []exposureClass `json:"classes"`
}

type exposureClass struct {
	ID           string  `json:"id"`
	Description  string  `json:"description"`
	AttackVector *string `json:"attackVector"`
	Reserved     bool    `json:"reserved"`
}

type matrixFile struct {
	Version    string `json:"version"`
	Techniques []struct {
		ID string `json:"id"`
	} `json:"techniques"`
	AttackClasses []struct {
		ID         string   `json:"id"`
		Techniques []string `json:"techniques"`
	} `json:"attackClasses"`
}

type canonicalFile struct {
	Classes map[string]struct {
		Primary   []string `json:"primary"`
		Secondary []string `json:"secondary"`
	} `json:"classes"`
}

type retiredRecord struct {
	ID           string `yaml:"id"`
	Disposition  string `yaml:"disposition"`
	SupersededBy string `yaml:"superseded_by"`
	RetiredAt    string `yaml:"retired_at"`
	RetiredIn    string `yaml:"retired_in"`
	Reason       string `yaml:"reason"`
}

type vendorFile struct {
	Repo    string `json:"repo"`
	Package string `json:"package"`
	Commit  string `json:"commit"`
	Version string `json:"version"`
}

type hmaCheckIDsFile struct {
	CheckIDs []string `json:"checkIds"`
}

// report collects the outcome of the run.
type report struct {
	out      io.Writer
	failures int
	warnings int
	checks   int
}

func (r *report) check(n int, name string, errs []string) {
	r.checks++
	if len(errs) == 0 {
		fmt.Fprintf(r.out, "ok   check %2d %s\n", n, name)
		return
	}
	for _, e := range errs {
		fmt.Fprintf(r.out, "FAIL check %2d %s: %s\n", n, name, e)
	}
	r.failures += len(errs)
}

func (r *report) warn(format string, args ...any) {
	r.warnings++
	fmt.Fprintf(r.out, "WARNING %s\n", fmt.Sprintf(format, args...))
}

func main() {
	root := flag.String("root", "../..", "repository root")
	writeCrosswalk := flag.Bool("write-crosswalk", false, "regenerate "+crosswalkPath+" instead of comparing it")
	flag.Parse()
	code := run(*root, *writeCrosswalk, os.Stdout)
	os.Exit(code)
}

// run executes every check and returns the process exit code.
func run(root string, writeCrosswalk bool, out io.Writer) int {
	r := &report{out: out}
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

	// Load the signature files.
	sigs, loadErrs := loadSignatures(root)

	// Check 1: schema validation.
	{
		var errs []string
		errs = append(errs, loadErrs...)
		sch, err := compileSchema(abs(schemaPath))
		if err != nil {
			errs = append(errs, fmt.Sprintf("compile %s: %v", schemaPath, err))
		} else {
			for _, s := range sigs {
				if err := sch.Validate(s.raw); err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", s.path, err))
				}
			}
		}
		r.check(1, fmt.Sprintf("schema 0.2 (%d signatures)", len(sigs)), errs)
	}

	// Check 2: id grammar re-checked in code, and id uniqueness.
	{
		var errs []string
		seen := map[string]string{}
		for _, s := range sigs {
			if !idGrammar.MatchString(s.sig.ID) {
				errs = append(errs, fmt.Sprintf("%s: id %q does not match the id grammar", s.path, s.sig.ID))
			}
			if prev, ok := seen[s.sig.ID]; ok {
				errs = append(errs, fmt.Sprintf("%s: id %q already used by %s", s.path, s.sig.ID, prev))
			}
			seen[s.sig.ID] = s.path
		}
		r.check(2, "id grammar", errs)
	}

	// Check 3: family registry and directory layout.
	fams, famErr := readJSON[familiesFile](abs(familiesPath))
	{
		var errs []string
		if famErr != nil {
			errs = append(errs, famErr.Error())
		}
		byToken := map[string]family{}
		if famErr == nil {
			tokenRE, err := regexp.Compile(fams.TokenPattern)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: tokenPattern: %v", familiesPath, err))
			}
			for _, f := range fams.Families {
				if tokenRE != nil && !tokenRE.MatchString(f.Token) {
					errs = append(errs, fmt.Sprintf("%s: token %q does not match tokenPattern", familiesPath, f.Token))
				}
				if f.Status != "frozen" && f.Status != "open" {
					errs = append(errs, fmt.Sprintf("%s: token %q status %q is not frozen or open", familiesPath, f.Token, f.Status))
				}
				if f.Status == "frozen" && len(f.IDs) == 0 {
					errs = append(errs, fmt.Sprintf("%s: frozen token %q has no ids allowlist", familiesPath, f.Token))
				}
				byToken[f.Token] = f
			}
		}
		for _, s := range sigs {
			m := idGrammar.FindStringSubmatch(s.sig.ID)
			if m == nil {
				continue // reported by check 2
			}
			token := m[1]
			f, ok := byToken[token]
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: family token %q is not registered in %s", s.path, token, familiesPath))
			} else {
				if f.Status == "frozen" && !contains(f.IDs, s.sig.ID) {
					errs = append(errs, fmt.Sprintf("%s: family %q is frozen and %s is not in its allowlist", s.path, token, s.sig.ID))
				}
				if f.Category != s.sig.Category {
					errs = append(errs, fmt.Sprintf("%s: family %q is category %q but the signature is %q", s.path, token, f.Category, s.sig.Category))
				}
			}
			dir := filepath.Base(filepath.Dir(s.path))
			if dir != strings.ToLower(token) {
				errs = append(errs, fmt.Sprintf("%s: directory %q must equal the family token lowercased (%q)", s.path, dir, strings.ToLower(token)))
			}
			if base := filepath.Base(s.path); base != s.sig.ID+".yaml" {
				errs = append(errs, fmt.Sprintf("%s: file name must be %s.yaml", s.path, s.sig.ID))
			}
		}
		r.check(3, "family registry and layout", errs)
	}

	// Load the matrix, the canonical classes and the exposure classes.
	matrix, matrixErr := readJSON[matrixFile](abs(matrixPath))
	canonical, canonicalErr := readJSON[canonicalFile](abs(canonicalPath))
	exposure, exposureErr := readJSON[exposureFile](abs(exposurePath))
	techniqueSet := map[string]bool{}
	vectorTechniques := map[string][]string{}
	if matrixErr == nil {
		for _, t := range matrix.Techniques {
			techniqueSet[t.ID] = true
		}
		for _, c := range matrix.AttackClasses {
			vectorTechniques[c.ID] = c.Techniques
		}
	}
	primaryClass := map[string]string{} // technique id -> canonical class
	if canonicalErr == nil {
		for name, c := range canonical.Classes {
			for _, t := range c.Primary {
				primaryClass[t] = name
			}
		}
	}
	exposureByID := map[string]exposureClass{}
	if exposureErr == nil {
		for _, c := range exposure.Classes {
			exposureByID[c.ID] = c
		}
	}

	// Check 4: technique ids resolve in the matrix snapshot.
	{
		var errs []string
		if matrixErr != nil {
			errs = append(errs, matrixErr.Error())
		}
		for _, s := range sigs {
			if !techniqueGrammar.MatchString(s.sig.TechniqueID) {
				errs = append(errs, fmt.Sprintf("%s: technique_id %q does not match ^T-dddd(.ddd)?$", s.path, s.sig.TechniqueID))
			} else if matrixErr == nil && !techniqueSet[s.sig.TechniqueID] {
				errs = append(errs, fmt.Sprintf("%s: technique_id %s is not in %s", s.path, s.sig.TechniqueID, matrixPath))
			}
			for _, t := range s.sig.RelatedTechniqueIDs {
				if t == s.sig.TechniqueID {
					errs = append(errs, fmt.Sprintf("%s: related_technique_ids repeats the primary %s", s.path, t))
				}
				if !techniqueGrammar.MatchString(t) {
					errs = append(errs, fmt.Sprintf("%s: related technique %q does not match ^T-dddd(.ddd)?$", s.path, t))
				} else if matrixErr == nil && !techniqueSet[t] {
					errs = append(errs, fmt.Sprintf("%s: related technique %s is not in %s", s.path, t, matrixPath))
				}
			}
		}
		r.check(4, "technique ids resolve in the matrix snapshot", errs)
	}

	// Check 5: injection attack_class is canonical and derived from technique_id.
	{
		var errs []string
		if canonicalErr != nil {
			errs = append(errs, canonicalErr.Error())
		}
		for _, s := range sigs {
			if s.sig.Category != "injection" {
				continue
			}
			if canonicalErr != nil {
				break
			}
			if _, ok := canonical.Classes[s.sig.AttackClass]; !ok {
				errs = append(errs, fmt.Sprintf("%s: attack_class %q is not a class in %s", s.path, s.sig.AttackClass, canonicalPath))
				continue
			}
			want, ok := primaryClass[s.sig.TechniqueID]
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: technique_id %s is in no primary list of %s, so no attack_class can be derived", s.path, s.sig.TechniqueID, canonicalPath))
				continue
			}
			if want != s.sig.AttackClass {
				errs = append(errs, fmt.Sprintf("%s: attack_class is %q but technique_id %s is primary to %q", s.path, s.sig.AttackClass, s.sig.TechniqueID, want))
			}
		}
		r.check(5, "injection attack_class matches the canonical primary class", errs)
	}

	// Check 6: attack_vector is a matrix attack class carrying technique_id.
	{
		var errs []string
		for _, s := range sigs {
			if s.sig.AttackVector == "" {
				continue
			}
			if matrixErr != nil {
				errs = append(errs, matrixErr.Error())
				break
			}
			techs, ok := vectorTechniques[s.sig.AttackVector]
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: attack_vector %q is not an attackClasses id in %s", s.path, s.sig.AttackVector, matrixPath))
				continue
			}
			if !contains(techs, s.sig.TechniqueID) {
				errs = append(errs, fmt.Sprintf("%s: technique_id %s is not in the techniques list of attack_vector %s (%s)", s.path, s.sig.TechniqueID, s.sig.AttackVector, strings.Join(techs, ", ")))
			}
		}
		r.check(6, "attack_vector is a matrix attack class carrying technique_id", errs)
	}

	// Check 7: exposure_class is registered and its attack_vector join holds.
	{
		var errs []string
		if exposureErr != nil {
			errs = append(errs, exposureErr.Error())
		}
		for _, s := range sigs {
			if s.sig.Category != "exposure" || exposureErr != nil {
				continue
			}
			c, ok := exposureByID[s.sig.ExposureClass]
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: exposure_class %q is not in %s", s.path, s.sig.ExposureClass, exposurePath))
				continue
			}
			if c.AttackVector == nil && s.sig.AttackVector != "" {
				errs = append(errs, fmt.Sprintf("%s: %s joins to no attack_vector but the signature carries %q", s.path, c.ID, s.sig.AttackVector))
			}
			if c.AttackVector != nil && s.sig.AttackVector != "" && s.sig.AttackVector != *c.AttackVector {
				errs = append(errs, fmt.Sprintf("%s: %s joins to attack_vector %s but the signature carries %q", s.path, c.ID, *c.AttackVector, s.sig.AttackVector))
			}
		}
		r.check(7, "exposure_class registered with its attack_vector join", errs)
	}

	// Check 8: the three vocabularies are pairwise disjoint, case-insensitively.
	{
		var errs []string
		owner := map[string]string{}
		add := func(set string, id string) {
			k := strings.ToLower(id)
			if prev, ok := owner[k]; ok && prev != set {
				errs = append(errs, fmt.Sprintf("%q appears in both %s and %s", id, prev, set))
			}
			owner[k] = set
		}
		if canonicalErr == nil {
			for name := range canonical.Classes {
				add("canonical classes", name)
			}
		}
		if matrixErr == nil {
			for _, c := range matrix.AttackClasses {
				add("matrix attackClasses", c.ID)
			}
		}
		if exposureErr == nil {
			for _, c := range exposure.Classes {
				add("exposure classes", c.ID)
			}
		}
		r.check(8, "canonical classes, matrix vectors and exposure classes are disjoint", errs)
	}

	// Check 9: a fixture with enough cases exists for every signature.
	fixtures := map[string]Fixture{}
	{
		var errs []string
		idSet := map[string]bool{}
		for _, s := range sigs {
			idSet[s.sig.ID] = true
			p := filepath.Join(fixturesDir, s.sig.ID+".json")
			fx, err := readJSON[Fixture](abs(p))
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", p, err))
				continue
			}
			if fx.Signature != s.sig.ID {
				errs = append(errs, fmt.Sprintf("%s: signature field is %q, want %q", p, fx.Signature, s.sig.ID))
			}
			if len(fx.ShouldMatch) < minFixtureCases {
				errs = append(errs, fmt.Sprintf("%s: %d shouldMatch cases, need at least %d", p, len(fx.ShouldMatch), minFixtureCases))
			}
			if len(fx.ShouldNotMatch) < minFixtureCases {
				errs = append(errs, fmt.Sprintf("%s: %d shouldNotMatch cases, need at least %d", p, len(fx.ShouldNotMatch), minFixtureCases))
			}
			fixtures[s.sig.ID] = fx
		}
		extra, _ := filepath.Glob(filepath.Join(abs(fixturesDir), "*.json"))
		for _, f := range extra {
			id := strings.TrimSuffix(filepath.Base(f), ".json")
			if !idSet[id] {
				errs = append(errs, fmt.Sprintf("%s/%s.json has no signature", fixturesDir, id))
			}
		}
		r.check(9, "fixtures present with at least three cases each way", errs)
	}

	// Check 10: every fixture case runs through the real matcher.
	{
		var errs []string
		for _, s := range sigs {
			if s.matcher == nil {
				errs = append(errs, fmt.Sprintf("%s: match block did not compile (see check 1)", s.path))
				continue
			}
			fx, ok := fixtures[s.sig.ID]
			if !ok {
				continue
			}
			for _, c := range fx.ShouldMatch {
				doc, err := caseText(c)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s/%s: %v", s.sig.ID, c.Name, err))
					continue
				}
				if !s.matcher.Match(doc) {
					errs = append(errs, fmt.Sprintf("%s/%s should MATCH: %q", s.sig.ID, c.Name, doc))
				}
			}
			for _, c := range fx.ShouldNotMatch {
				doc, err := caseText(c)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s/%s: %v", s.sig.ID, c.Name, err))
					continue
				}
				if s.matcher.Match(doc) {
					errs = append(errs, fmt.Sprintf("%s/%s should NOT match: %q", s.sig.ID, c.Name, doc))
				}
			}
		}
		r.check(10, "fixture cases agree with the matcher", errs)
	}

	// Check 11: retired ids.
	{
		var errs []string
		live := map[string]bool{}
		for _, s := range sigs {
			live[s.sig.ID] = true
		}
		records, err := readRetired(abs(retiredPath))
		if err != nil {
			errs = append(errs, err.Error())
		}
		retired := map[string]bool{}
		for _, rec := range records {
			if retired[rec.ID] {
				errs = append(errs, fmt.Sprintf("%s: %s is recorded twice", retiredPath, rec.ID))
			}
			retired[rec.ID] = true
		}
		for _, rec := range records {
			if !retiredUnionGrammar.MatchString(rec.ID) {
				errs = append(errs, fmt.Sprintf("%s: id %q does not match the union grammar", retiredPath, rec.ID))
			}
			switch rec.Disposition {
			case "retired":
				if rec.SupersededBy != "" {
					errs = append(errs, fmt.Sprintf("%s: %s is retired but carries superseded_by", retiredPath, rec.ID))
				}
			case "superseded", "superseded_narrowed":
				if rec.SupersededBy == "" {
					errs = append(errs, fmt.Sprintf("%s: %s is %s but has no superseded_by", retiredPath, rec.ID, rec.Disposition))
				} else {
					if retired[rec.SupersededBy] {
						errs = append(errs, fmt.Sprintf("%s: %s is superseded by %s, which is itself retired (chains are not allowed)", retiredPath, rec.ID, rec.SupersededBy))
					} else if !live[rec.SupersededBy] {
						errs = append(errs, fmt.Sprintf("%s: %s is superseded by %s, which is not a live signature", retiredPath, rec.ID, rec.SupersededBy))
					}
				}
			default:
				errs = append(errs, fmt.Sprintf("%s: %s has disposition %q, want retired, superseded or superseded_narrowed", retiredPath, rec.ID, rec.Disposition))
			}
			if live[rec.ID] {
				errs = append(errs, fmt.Sprintf("%s: %s is retired and also a live signature", retiredPath, rec.ID))
			}
			if !retiredDate.MatchString(rec.RetiredAt) {
				errs = append(errs, fmt.Sprintf("%s: %s retired_at %q is not a calendar date", retiredPath, rec.ID, rec.RetiredAt))
			}
			if rec.RetiredIn == "" {
				errs = append(errs, fmt.Sprintf("%s: %s has no retired_in", retiredPath, rec.ID))
			}
			if strings.TrimSpace(rec.Reason) == "" {
				errs = append(errs, fmt.Sprintf("%s: %s has no reason", retiredPath, rec.ID))
			}
		}
		// 11b: every signature present at the merge base must be live or retired.
		baseIDs, err := signatureIDsAtMergeBase(root)
		if err != nil {
			r.warn("check 11b skipped, git unavailable: %v", err)
		} else {
			for _, id := range baseIDs {
				if !live[id] && !retired[id] {
					errs = append(errs, fmt.Sprintf("%s was a signature at the merge base and is now absent without a record in %s", id, retiredPath))
				}
			}
		}
		r.check(11, fmt.Sprintf("retired ids (%d records)", len(records)), errs)
	}

	// Check 12: the technique crosswalk is current.
	{
		var errs []string
		want := buildCrosswalk(sigs)
		p := abs(crosswalkPath)
		if writeCrosswalk {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				errs = append(errs, err.Error())
			} else if err := os.WriteFile(p, want, 0o644); err != nil {
				errs = append(errs, err.Error())
			} else {
				fmt.Fprintf(out, "wrote %s\n", crosswalkPath)
			}
		} else {
			got, err := os.ReadFile(p)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%v (run with -write-crosswalk)", err))
			} else if !bytes.Equal(got, want) {
				errs = append(errs, fmt.Sprintf("%s is stale; run `go run -mod=vendor . -write-crosswalk` and commit it", crosswalkPath))
			}
		}
		r.check(12, "technique crosswalk is current", errs)
	}

	// Check 13: vendor manifests and HackMyAgent check ids.
	{
		var errs []string
		mv, err := readJSON[vendorFile](abs(matrixVendorPath))
		if err != nil {
			errs = append(errs, err.Error())
		} else if !fortyHex.MatchString(mv.Commit) && mv.Version == "" {
			errs = append(errs, fmt.Sprintf("%s: needs a 40 character commit or a version", matrixVendorPath))
		}
		hv, err := readJSON[vendorFile](abs(hmaVendorPath))
		if err != nil {
			errs = append(errs, err.Error())
		} else if !fortyHex.MatchString(hv.Commit) && hv.Version == "" {
			errs = append(errs, fmt.Sprintf("%s: needs a 40 character commit or a version", hmaVendorPath))
		}
		ids, err := readJSON[hmaCheckIDsFile](abs(hmaCheckIDsPath))
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			known := map[string]bool{}
			for _, id := range ids.CheckIDs {
				known[id] = true
			}
			for _, s := range sigs {
				for _, id := range s.sig.HMACheckIDs {
					if !known[id] {
						errs = append(errs, fmt.Sprintf("%s: hma_check_ids %q is not in %s", s.path, id, hmaCheckIDsPath))
					}
				}
			}
		}
		r.check(13, "vendor manifests and hma_check_ids resolve", errs)
	}

	// Provenance completeness is advisory.
	for _, s := range sigs {
		if s.sig.Status != "active" || s.sig.Provenance == nil {
			continue
		}
		if s.sig.Provenance.Source == "" {
			r.warn("%s is active without provenance.source", s.sig.ID)
		}
		if s.sig.Provenance.FirstSeen == "" {
			r.warn("%s is active without provenance.first_seen", s.sig.ID)
		}
	}

	fmt.Fprintf(out, "\n%d of %d checks reported, %d failure(s), %d warning(s)\n", r.checks, totalChecks, r.failures, r.warnings)
	if r.failures > 0 {
		return 1
	}
	return 0
}

// loadSignatures reads every signatures/**/*.yaml. Load errors are returned
// as strings so check 1 can report them; a file that fails to load is
// excluded from the later checks.
func loadSignatures(root string) ([]loadedSignature, []string) {
	var sigs []loadedSignature
	var errs []string
	dir := filepath.Join(root, signaturesDir)
	var files []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	if len(files) == 0 {
		errs = append(errs, fmt.Sprintf("no signature files under %s", signaturesDir))
	}
	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		s, err := loadSignatureFile(f)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		s.path = rel
		sigs = append(sigs, s)
	}
	return sigs, errs
}

// loadSignatureFile parses one YAML file into a JSON compatible document
// (for the schema) and a typed Signature (for the cross-checks).
func loadSignatureFile(path string) (loadedSignature, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return loadedSignature{}, err
	}
	return parseSignature(b)
}

func parseSignature(b []byte) (loadedSignature, error) {
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return loadedSignature{}, fmt.Errorf("yaml: %w", err)
	}
	jb, err := json.Marshal(doc)
	if err != nil {
		return loadedSignature{}, fmt.Errorf("yaml document is not JSON compatible: %w", err)
	}
	raw, err := jsonschema.UnmarshalJSON(bytes.NewReader(jb))
	if err != nil {
		return loadedSignature{}, err
	}
	var sig Signature
	if err := json.Unmarshal(jb, &sig); err != nil {
		return loadedSignature{}, fmt.Errorf("decode: %w", err)
	}
	if sig.ID == "" {
		return loadedSignature{}, fmt.Errorf("no id")
	}
	ls := loadedSignature{raw: raw, sig: sig}
	if m, err := compileMatch(sig.Match); err == nil {
		ls.matcher = m
	}
	return ls, nil
}

// compileSchema compiles the schema with format assertions on.
func compileSchema(path string) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	return c.Compile(path)
}

// caseText resolves a fixture case to its document: the text field, or the
// hex codepoints joined.
func caseText(c FixtureCase) (string, error) {
	if len(c.Codepoints) == 0 {
		return c.Text, nil
	}
	var sb strings.Builder
	for _, h := range c.Codepoints {
		v, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			return "", fmt.Errorf("codepoint %q: %w", h, err)
		}
		sb.WriteRune(rune(v))
	}
	return sb.String(), nil
}

func readJSON[T any](path string) (T, error) {
	var v T
	b, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return v, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return v, nil
}

func readRetired(path string) ([]retiredRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []retiredRecord
	if err := yaml.Unmarshal(b, &records); err != nil {
		return nil, fmt.Errorf("%s: %w", retiredPath, err)
	}
	return records, nil
}

// signatureIDsAtMergeBase lists the signature ids committed at the merge
// base of HEAD and origin/main. Any error means git is unavailable here.
func signatureIDsAtMergeBase(root string) ([]string, error) {
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(stdout.String()), nil
	}
	base, err := git("merge-base", "HEAD", "origin/main")
	if err != nil {
		return nil, err
	}
	list, err := git("ls-tree", "-r", "--name-only", base, "--", signaturesDir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, ".yaml") {
			ids = append(ids, strings.TrimSuffix(filepath.Base(line), ".yaml"))
		}
	}
	return ids, nil
}

// buildCrosswalk renders crosswalks/technique-signatures.json: byTechnique
// maps every technique (primary or related) to the sorted signature ids
// that evidence it; bySignature records each signature's primary and
// related techniques.
func buildCrosswalk(sigs []loadedSignature) []byte {
	type entry struct {
		TechniqueID         string   `json:"techniqueId"`
		RelatedTechniqueIDs []string `json:"relatedTechniqueIds"`
	}
	byTechnique := map[string][]string{}
	bySignature := map[string]entry{}
	for _, s := range sigs {
		related := append([]string{}, s.sig.RelatedTechniqueIDs...)
		sort.Strings(related)
		bySignature[s.sig.ID] = entry{TechniqueID: s.sig.TechniqueID, RelatedTechniqueIDs: related}
		byTechnique[s.sig.TechniqueID] = append(byTechnique[s.sig.TechniqueID], s.sig.ID)
		for _, t := range related {
			byTechnique[t] = append(byTechnique[t], s.sig.ID)
		}
	}
	for t := range byTechnique {
		sort.Strings(byTechnique[t])
	}
	doc := struct {
		ByTechnique map[string][]string `json:"byTechnique"`
		BySignature map[string]entry    `json:"bySignature"`
	}{byTechnique, bySignature}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc) // Encode appends the trailing newline; map keys are sorted.
	return buf.Bytes()
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

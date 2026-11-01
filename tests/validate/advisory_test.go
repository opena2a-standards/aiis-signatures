package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The advisory keys these tests need are glued together when the tests run,
// from fragments that are not keys themselves, so no file of this repository
// carries one. The year 0000 is one no advisory carries.

// glue joins fragments into one string at run time.
func glue(parts ...string) string { return strings.Join(parts, "") }

var (
	testCVE  = glue("CVE", "-0000-0001")
	testGHSA = glue("GHSA", "-0000-0000-0000")
	testNVD  = glue("https://nvd", ".nist.gov/vuln/detail/", testCVE)
)

// The wording check 14 prints, pinned here.
const (
	wantAdvisoryCheckName = "no advisory id or advisory URL in signatures or fixtures"
	wantAdvisoryRuleText  = "a signature describes a class and names no individual advisory: it names its class, technique ids and CWE ids instead"

	kindCVE  = "an advisory id in the CVE form"
	kindGHSA = "an advisory id in the GHSA form"
	kindOSV  = "an OSV database advisory id"
	kindDist = "a distribution security advisory id"
	kindSec  = "a security advisory id"
	kindURL  = "an advisory URL"
)

// advisoryFailure is the check 14 line for one key: the file, the line, the
// field or "the line", and the kind of key. It never holds the key itself.
func advisoryFailure(rel string, line int, where, kind string) string {
	return fmt.Sprintf("FAIL check 14 %s: %s:%d: %s carries %s; %s", wantAdvisoryCheckName, rel, line, where, kind, wantAdvisoryRuleText)
}

// advisoryFailureAt is the check 14 line for a key in a file's path.
func advisoryFailureAt(rel, where, kind string) string {
	return fmt.Sprintf("FAIL check 14 %s: %s: %s carries %s; %s", wantAdvisoryCheckName, rel, where, kind, wantAdvisoryRuleText)
}

// copyCorpus copies what the validator reads into a temporary root.
func copyCorpus(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	for _, rel := range []string{signaturesDir, fixturesDir, "schema", "vendor", "crosswalks", retiredPath} {
		src := filepath.Join(repoRoot, filepath.FromSlash(rel))
		err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			r, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, r)
			if d.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// rewrite replaces the first old in one file of root with new.
func rewrite(t *testing.T, root, rel, old, new string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(old)) {
		t.Fatalf("%s does not contain %q", rel, old)
	}
	if err := os.WriteFile(p, bytes.Replace(b, []byte(old), []byte(new), 1), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeFile writes one new file under root.
func writeFile(t *testing.T, root, rel, text string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// lineOf returns the 1-based line of the first s in one file of root.
func lineOf(t *testing.T, root, rel, s string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte(s))
	if i < 0 {
		t.Fatalf("%s does not contain %q", rel, s)
	}
	return bytes.Count(b[:i], []byte("\n")) + 1
}

// runCheck14 runs the validator on root and returns its exit code and the
// lines check 14 printed. A failure of any other check fails the test, so
// each case shows that only check 14 reacts to it.
func runCheck14(t *testing.T, root string) (int, []string) {
	t.Helper()
	var out bytes.Buffer
	code := run(root, false, &out)
	var lines []string
	for _, l := range strings.Split(out.String(), "\n") {
		switch {
		case strings.HasPrefix(l, "ok   check 14 "), strings.HasPrefix(l, "FAIL check 14 "):
			lines = append(lines, l)
		case strings.HasPrefix(l, "FAIL "):
			t.Errorf("a check other than 14 failed: %s", l)
		}
	}
	return code, lines
}

// expectCheck14 compares check 14's lines and the exit code with the want.
func expectCheck14(t *testing.T, code int, got []string, wantCode int, want []string) {
	t.Helper()
	if code != wantCode {
		t.Errorf("validator exit %d, want %d", code, wantCode)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("check 14 printed:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// An advisory URL added to a signature's references fails check 14. The
// failure names the file, the line and the field, and repeats neither the
// URL nor the id in it.
func TestAdvisoryURLInReferencesFails(t *testing.T) {
	root := copyCorpus(t)
	rel := "signatures/exposure/AIIS-EXPOSURE-CHROMA-HEARTBEAT-01.yaml"
	rewrite(t, root, rel, "references:\n", "references:\n  - "+testNVD+"\n")
	line := lineOf(t, root, rel, testNVD)
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, []string{
		advisoryFailure(rel, line, "field references[0]", kindCVE),
		advisoryFailure(rel, line, "field references[0]", kindURL),
	})
}

// An advisory id in a signature's description fails check 14 on the line
// that carries it, inside the block the description spans.
func TestAdvisoryIDInDescriptionFails(t *testing.T) {
	root := copyCorpus(t)
	rel := "signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml"
	last := "  page understanding will be exposed to this.\n"
	rewrite(t, root, rel, last, last+"  It covers "+testCVE+".\n")
	line := lineOf(t, root, rel, testCVE)
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, []string{
		advisoryFailure(rel, line, "field description", kindCVE),
	})
}

// An advisory id in the label of a fixture case fails check 14.
func TestAdvisoryIDInFixtureCaseNameFails(t *testing.T) {
	root := copyCorpus(t)
	rel := "tests/fixtures/AIIS-ATTR-IGNORE-INST-01.json"
	rewrite(t, root, rel, `"name": "ignore-previous"`, `"name": "ignore-previous `+testGHSA+`"`)
	line := lineOf(t, root, rel, testGHSA)
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, []string{
		advisoryFailure(rel, line, "field shouldMatch[0].name", kindGHSA),
	})
}

// Control: the corpus as committed passes check 14.
func TestCorpusCarriesNoAdvisoryKey(t *testing.T) {
	code, got := runCheck14(t, repoRoot)
	expectCheck14(t, code, got, 0, []string{"ok   check 14 " + wantAdvisoryCheckName})
}

// Every form check 14 knows fails it, one comment line each, and each line
// is reported with every kind of key it carries.
func TestEveryAdvisoryFormFails(t *testing.T) {
	cases := []struct {
		key   string
		kinds []string // in the order check 14 reports them
	}{
		{testCVE, []string{kindCVE}},
		{strings.ToLower(testCVE), []string{kindCVE}},
		{glue("CVE", "-0000-0000001"), []string{kindCVE}},
		{glue("DEBIAN-CVE", "-0000-0001"), []string{kindCVE}},
		{testGHSA, []string{kindGHSA}},
		{glue("ghsa", "-wxyz-2345-6789"), []string{kindGHSA}},
		{glue("PYSEC", "-0000-0"), []string{kindOSV}},
		{glue("RUSTSEC", "-0000-0000"), []string{kindOSV}},
		{glue("GO", "-0000-0000"), []string{kindOSV}},
		{glue("GSD", "-0000-0000"), []string{kindOSV}},
		{glue("MAL", "-0000-0"), []string{kindOSV}},
		{glue("HSEC", "-0000-0000"), []string{kindOSV}},
		{glue("MGASA", "-0000-0000"), []string{kindOSV}},
		{glue("OESA", "-0000-0000"), []string{kindOSV}},
		{glue("OSV", "-0000-x0y0"), []string{kindOSV}},
		{glue("ASB", "-A-000000000"), []string{kindOSV}},
		{glue("PUB", "-A-000000000"), []string{kindOSV}},
		{glue("RHSA", "-0000:0000"), []string{kindDist}},
		{glue("RHBA", "-0000:0000"), []string{kindDist}},
		{glue("RHEA", "-0000:0000"), []string{kindDist}},
		{glue("ALSA", "-0000:0000"), []string{kindDist}},
		{glue("ALBA", "-0000:0000"), []string{kindDist}},
		{glue("ALEA", "-0000:0000"), []string{kindDist}},
		{glue("RLSA", "-0000:0000"), []string{kindDist}},
		{glue("SUSE", "-SU-0000:0000-0"), []string{kindDist}},
		{glue("SUSE", "-RU-0000:0000-0"), []string{kindDist}},
		{glue("SUSE", "-FU-0000:0000-0"), []string{kindDist}},
		{glue("SUSE", "-OU-0000:0000-0"), []string{kindDist}},
		{glue("openSUSE", "-SU-0000:0000-0"), []string{kindDist}},
		{glue("DSA", "-0000-0"), []string{kindDist}},
		{glue("DLA", "-0000-0"), []string{kindDist}},
		{glue("DTSA", "-000-0"), []string{kindDist}},
		{glue("ELA", "-0000-0"), []string{kindDist}},
		{glue("USN", "-0000-0"), []string{kindDist}},
		{glue("LSN", "-0000-0"), []string{kindDist}},
		{glue("MS00", "-000"), []string{kindSec}},
		{glue("ADV", "000000"), []string{kindSec}},
		{glue("VMSA", "-0000-0000"), []string{kindSec}},
		{glue("ZDI", "-00-0000"), []string{kindSec}},
		{glue("ZDI", "-CAN-0000"), []string{kindSec}},
		{glue("JVNDB", "-0000-000000"), []string{kindSec}},
		{glue("JVN", "#00000000"), []string{kindSec}},
		{glue("JVNVU", "#00000000"), []string{kindSec}},
		{glue("CNVD", "-0000-00000"), []string{kindSec}},
		{glue("CNNVD", "-000000-0000"), []string{kindSec}},
		{glue("BDU", ":0000-00000"), []string{kindSec}},
		{glue("EUVD", "-0000-0000"), []string{kindSec}},
		{glue("ICSA", "-00-000-00"), []string{kindSec}},
		{glue("VU", "#000000"), []string{kindSec}},
		{glue("TALOS", "-0000-0000"), []string{kindSec}},
		{glue("cisco", "-sa-example"), []string{kindSec}},
		{glue("FG", "-IR-00-000"), []string{kindSec}},
		{glue("SSA", "-000000"), []string{kindSec}},
		{glue("NTAP", "-00000000-0000"), []string{kindSec}},
		{glue("SNYK", "-JS-EXAMPLE-0000000"), []string{kindSec}},
		{testNVD, []string{kindCVE, kindURL}},
		{glue("https://github.com/", "advisories/", testGHSA), []string{kindGHSA, kindURL}},
		{glue("https://github.com/example/example/security/", "advisories/", testGHSA), []string{kindGHSA, kindURL}},
		{glue("https://osv", ".dev/vulnerability/", "OSV", "-0000-x0y0"), []string{kindOSV, kindURL}},
		{glue("https://www.cve", ".org/CVERecord?id=", testCVE), []string{kindCVE, kindURL}},
		{glue("https://cve.mitre", ".org/cgi-bin/cvename.cgi?name=", testCVE), []string{kindCVE, kindURL}},
		{glue("https://www.cisa", ".gov/known-exploited-vulnerabilities-catalog"), []string{kindURL}},
		{glue("https://access.redhat", ".com/errata/", "RHSA", "-0000:0000"), []string{kindDist, kindURL}},
		{glue("https://access.redhat", ".com/security/cve/", testCVE), []string{kindCVE, kindURL}},
		{glue("https://ubuntu", ".com/security/notices/", "USN", "-0000-0"), []string{kindDist, kindURL}},
		{glue("https://ubuntu", ".com/security/", testCVE), []string{kindCVE, kindURL}},
		{glue("https://security-tracker.debian", ".org/tracker/", testCVE), []string{kindCVE, kindURL}},
		{glue("https://www.debian", ".org/security/0000/dsa-0000"), []string{kindURL}},
		{glue("https://www.debian", ".org/lts/security/0000/dla-0000"), []string{kindURL}},
		{glue("https://msrc.microsoft", ".com/update-guide/vulnerability/", testCVE), []string{kindCVE, kindURL}},
		{glue("https://security.snyk", ".io/vuln/", "SNYK", "-JS-EXAMPLE-0000000"), []string{kindSec, kindURL}},
		{glue("https://rustsec", ".org/advisories/", "RUSTSEC", "-0000-0000"), []string{kindOSV, kindURL}},
		{glue("https://pkg.go", ".dev/vuln/", "GO", "-0000-0000"), []string{kindOSV, kindURL}},
		{glue("https://huntr", ".com/bounties/00000000-0000-0000-0000-000000000000"), []string{kindURL}},
		{glue("https://huntr", ".dev/bounties/00000000-0000-0000-0000-000000000000"), []string{kindURL}},
		{glue("https://www.zerodayinitiative", ".com/advisories/", "ZDI", "-00-0000/"), []string{kindSec, kindURL}},
		{glue("https://euvd.enisa", ".europa.eu/vulnerability/", "EUVD", "-0000-0000"), []string{kindSec, kindURL}},
		{glue("https://advisories", ".gitlab.com/pkg/npm/example/", testCVE), []string{kindCVE, kindURL}},
		{glue("https://kb.cert", ".org/vuls/id/000000"), []string{kindURL}},
		{glue("https://jvn", ".jp/en/jp/JVN00000000/"), []string{kindURL}},
		{glue("https://jvndb.jvn", ".jp/en/contents/0000/", "JVNDB", "-0000-000000.html"), []string{kindSec, kindURL}},
		{glue("https://vuldb", ".com/?id.000000"), []string{kindURL}},
		{glue("https://wpscan", ".com/vulnerability/00000000-0000-0000-0000-000000000000"), []string{kindURL}},
		{glue("https://example.com/security/", "advisories/0000"), []string{kindURL}},
		{glue("https://example.com/", "advisory/0000"), []string{kindURL}},
		{glue("https://example.com/security-", "advisory-0000"), []string{kindURL}},
		{glue("https://example.com/support/security-", "bulletin-0000"), []string{kindURL}},
		{glue("https://example.com/", "psirt/0000"), []string{kindURL}},
	}
	root := copyCorpus(t)
	rel := "signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml"
	p := filepath.Join(root, filepath.FromSlash(rel))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Fatalf("%s does not end with a newline", rel)
	}
	first := bytes.Count(b, []byte("\n")) + 1
	var want []string
	for i, c := range cases {
		b = append(b, "# "+c.key+"\n"...)
		for _, kind := range c.kinds {
			want = append(want, advisoryFailure(rel, first+i, "the line", kind))
		}
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, want)
}

// Text that resembles an advisory key but is not one passes check 14: the
// ids and URLs a signature does carry, and near misses of each form.
func TestAdvisoryNearMissesPass(t *testing.T) {
	nearMisses := []string{
		"T-2001", "T-1001.001", "AIIS-ATTR-IGNORE-INST-01", "AIIS-0001", "CWE-74", "CWE-200",
		"CVE-000-0001", "CVE-0000-001", "CVE 0000 0001", "GHSA-0000-0000",
		"GO-0000", "ALGO-0000-0000", "go-1.22", "RHSA-0000", "USN-00-0", "ELA-00-0", "DSA-1024",
		"MS-0000", "ms 00-000", "VU-000000", "snyk-cli-1.0", "0.5.13-rc1", "203.0.113.10",
		"https://arxiv.org/abs/2306.05499",
		"https://github.com/ollama/ollama/blob/main/docs/api.md",
		"https://github.com/example/example/security/policy",
		"https://example.com/advisor/0000", "https://example.com/advisors/",
	}
	root := copyCorpus(t)
	sig := "signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml"
	last := "  page understanding will be exposed to this.\n"
	rewrite(t, root, sig, last, last+"  "+strings.Join(nearMisses, " ")+"\n")
	p := filepath.Join(root, filepath.FromSlash(sig))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range nearMisses {
		b = append(b, "# "+s+"\n"...)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	fx := "tests/fixtures/AIIS-ATTR-IGNORE-INST-01.json"
	rewrite(t, root, fx, `"note": "`, `"note": "`+strings.Join(nearMisses, " ")+` `)
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 0, []string{"ok   check 14 " + wantAdvisoryCheckName})
}

// A key written with escaped characters fails check 14: the YAML and JSON
// values are read as decoded, the way a reader of the files decodes them.
func TestEscapedAdvisoryKeysFail(t *testing.T) {
	root := copyCorpus(t)
	sig := "signatures/exposure/AIIS-EXPOSURE-CHROMA-HEARTBEAT-01.yaml"
	name := "name: Exposed Chroma vector database heartbeat\n"
	rewrite(t, root, sig, name, glue(`name: "Exposed Chroma vector database heartbeat \x43`, `VE-0000-0001"`, "\n"))
	fx := "tests/fixtures/AIIS-ATTR-IGNORE-INST-01.json"
	rewrite(t, root, fx, `"note": "`, glue(`"note": "\u0047`, `HSA-0000-0000-0000 https:\/\/nvd`, `.nist.gov\/vuln\/detail\/0 `))
	nameLine := lineOf(t, root, sig, `name: "`)
	noteLine := lineOf(t, root, fx, `"note": "`)
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, []string{
		advisoryFailure(sig, nameLine, "field name", kindCVE),
		advisoryFailure(fx, noteLine, "field note", kindGHSA),
		advisoryFailure(fx, noteLine, "field note", kindURL),
	})
}

// A fixture case given as codepoints is read as the text they spell, the
// way check 10 reads it.
func TestAdvisoryIDInCodepointsFails(t *testing.T) {
	root := copyCorpus(t)
	rel := "tests/fixtures/AIIS-UNICODE-TAG-BLOCK-01.json"
	var hex []string
	for _, r := range testGHSA {
		hex = append(hex, fmt.Sprintf("%q", fmt.Sprintf("%X", r)))
	}
	label := "spelled-in-codepoints"
	added := `    {"name": "` + label + `", "codepoints": [` + strings.Join(hex, ", ") + "]},\n"
	rewrite(t, root, rel, "\"shouldNotMatch\": [\n", "\"shouldNotMatch\": [\n"+added)
	line := lineOf(t, root, rel, label)
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, []string{
		advisoryFailure(rel, line, "field shouldNotMatch[0].codepoints (decoded)", kindGHSA),
	})
}

// Check 14 reads every file under signatures/ and tests/fixtures/, not only
// the signature and fixture files the other checks load.
func TestEveryFileUnderSignaturesAndFixturesIsRead(t *testing.T) {
	root := copyCorpus(t)
	notes := "signatures/exposure/notes.txt"
	readme := "tests/fixtures/README.md"
	writeFile(t, root, notes, "See "+testNVD+"\n")
	writeFile(t, root, readme, "Cases from\n"+testGHSA+".\n")
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 1, []string{
		advisoryFailure(notes, 1, "the line", kindCVE),
		advisoryFailure(notes, 1, "the line", kindURL),
		advisoryFailure(readme, 2, "the line", kindGHSA),
	})
}

// A failure never repeats the key, also when a file path or a mapping key
// carries it: the key is printed as <advisory key>.
func TestFailuresNeverRepeatTheKey(t *testing.T) {
	root := copyCorpus(t)
	notes := "signatures/notes/" + testGHSA + ".txt"
	writeFile(t, root, notes, "See "+testNVD+"\n")
	fx := "tests/fixtures/AIIS-ATTR-IGNORE-INST-01.json"
	rewrite(t, root, fx, `"note": `, `"x_`+testCVE+`": "a key that names an advisory",`+"\n  "+`"note": `)
	keyLine := lineOf(t, root, fx, `"x_`)
	code, got := runCheck14(t, root)
	shown := "signatures/notes/<advisory key>.txt"
	expectCheck14(t, code, got, 1, []string{
		advisoryFailureAt(shown, "the path", kindGHSA),
		advisoryFailure(shown, 1, "the line", kindCVE),
		advisoryFailure(shown, 1, "the line", kindURL),
		advisoryFailure(fx, keyLine, "key x_<advisory key>", kindCVE),
	})
	for _, l := range got {
		for _, key := range []string{testCVE, testGHSA, testNVD} {
			if strings.Contains(l, key) {
				t.Errorf("a check 14 line repeats a key: %s", l)
			}
		}
	}
}

// A run that reads no file fails check 14 instead of passing it.
func TestAdvisoryCheckFailsWhenItReadsNothing(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{signaturesDir, fixturesDir} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if code := run(root, false, &out); code != 1 {
		t.Errorf("validator exit %d, want 1", code)
	}
	want := "FAIL check 14 " + wantAdvisoryCheckName + ": read no file under signatures/ or tests/fixtures/\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, out.String())
	}
}

// The validator's own sources and test data carry no advisory key either:
// the tests glue every key they need together when they run. Each file is
// copied under signatures/ as text, so check 14 reads it as it would read a
// file of the corpus.
func TestValidatorSourcesCarryNoAdvisoryKey(t *testing.T) {
	root := copyCorpus(t)
	n := 0
	for _, pattern := range []string{"*.go", "capture/*.go", "testdata/*"} {
		files, err := filepath.Glob(filepath.FromSlash(pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			name := strings.ReplaceAll(filepath.ToSlash(f), "/", "-")
			writeFile(t, root, "signatures/sources/"+name+".txt", string(b))
			n++
		}
	}
	if n == 0 {
		t.Fatal("no validator source found")
	}
	code, got := runCheck14(t, root)
	expectCheck14(t, code, got, 0, []string{"ok   check 14 " + wantAdvisoryCheckName})
}

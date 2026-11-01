package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Check 14 keeps advisory keys out of the signature files and their
// fixtures. A signature describes a class of content and names no individual
// advisory: it names its class, its technique ids and its CWE ids instead.
//
// Every file under signatures/ and tests/fixtures/ is read twice: each line
// as written, which covers comments and files of any kind, and each key and
// string value of a YAML or JSON document as decoded, which covers escaped
// characters and fixture cases written as codepoints. The path of each file
// is read too. A failure names the file, the line, the field where there is
// one and the kind of key, and never the key: a key inside the file path or
// the field is printed as advisoryKeyMark, so the run log does not repeat it.

// advisoryRuleText closes every check 14 failure.
const advisoryRuleText = "a signature describes a class and names no individual advisory: it names its class, technique ids and CWE ids instead"

// advisoryKeyMark stands in for a key inside a printed file path or field.
const advisoryKeyMark = "<advisory key>"

// advisoryRule is one kind of advisory key and the forms it takes.
type advisoryRule struct {
	kind string
	re   *regexp.Regexp
}

// newAdvisoryRule compiles the forms of one kind, case-insensitively.
func newAdvisoryRule(kind string, forms ...string) advisoryRule {
	return advisoryRule{kind: kind, re: regexp.MustCompile(`(?i)(?:` + strings.Join(forms, `|`) + `)`)}
}

// advisoryRules are the kinds of key check 14 refuses, in the order a line
// that carries several is reported.
var advisoryRules = []advisoryRule{
	newAdvisoryRule("an advisory id in the CVE form",
		`CVE-[0-9]{4}-[0-9]{4,}`),
	newAdvisoryRule("an advisory id in the GHSA form",
		`GHSA(?:-[0-9a-z]{4}){3}`),
	// Database prefixes defined by the OSV schema, in the forms that carry
	// a year or a bulletin number.
	newAdvisoryRule("an OSV database advisory id",
		`\b(?:PYSEC|RUSTSEC|GO|GSD|MAL|HSEC|MGASA|OESA)-[0-9]{4}-[0-9]+`,
		`\bOSV-[0-9]{4}-[0-9a-z]+`,
		`\b(?:ASB|PUB)-A-[0-9]+`),
	newAdvisoryRule("a distribution security advisory id",
		`\b(?:RHSA|RHBA|RHEA|ALSA|ALBA|ALEA|RLSA)-[0-9]{4}:[0-9]+`,
		`\b(?:open)?SUSE-(?:SU|RU|FU|OU)-[0-9]{4}:[0-9]+`,
		`\b(?:DSA|DLA|DTSA|ELA|USN|LSN)-[0-9]{3,}-[0-9]+`),
	newAdvisoryRule("a security advisory id",
		`\bMS[0-9]{2}-[0-9]{3}\b`,
		`\bADV[0-9]{6}\b`,
		`\bVMSA-[0-9]{4}-[0-9]{4}`,
		`\bZDI-(?:[0-9]{2}-[0-9]{3,}|CAN-[0-9]+)`,
		`\bJVNDB-[0-9]{4}-[0-9]+`,
		`\bJVN(?:VU|TA)?#[0-9]{6,}`,
		`\bCNVD-[0-9]{4}-[0-9]+`,
		`\bCNNVD-[0-9]{6}-[0-9]+`,
		`\bBDU:[0-9]{4}-[0-9]+`,
		`\bEUVD-[0-9]{4}-[0-9]+`,
		`\bICSA-[0-9]{2}-[0-9]{3}-[0-9]{2}`,
		`\bVU#[0-9]{5,}`,
		`\bTALOS-[0-9]{4}-[0-9]{4}`,
		`\bcisco-sa-[0-9a-z]`,
		`\bFG-IR-[0-9]{2}-[0-9]{3}`,
		`\bSSA-[0-9]{6}`,
		`\bNTAP-[0-9]{8}-[0-9]{4}`,
		`\bSNYK-[0-9a-z]+-[0-9a-z._-]+-[0-9]{5,}\b`),
	// Advisory databases by host and path, then any URL whose path names an
	// advisory, a security bulletin or a product security response team.
	newAdvisoryRule("an advisory URL",
		`nvd\.nist\.gov/vuln/detail/`,
		`github\.com/advisories/`,
		`github\.com/[^/\s]+/[^/\s]+/security/advisories`,
		`osv\.dev/vulnerability/`,
		`cve\.org/cverecord`,
		`cve\.mitre\.org/cgi-bin/cvename`,
		`cisa\.gov/known-exploited-vulnerabilities`,
		`access\.redhat\.com/(?:errata|security/cve)/`,
		`ubuntu\.com/security/(?:notices/|cve-[0-9])`,
		`security-tracker\.debian\.org/tracker/`,
		`debian\.org/(?:lts/)?security/[0-9]{4}/`,
		`msrc\.microsoft\.com/update-guide/`,
		`snyk\.io/vuln/`,
		`rustsec\.org/advisories/`,
		`pkg\.go\.dev/vuln/`,
		`huntr\.(?:com|dev)/bounties/`,
		`zerodayinitiative\.com/advisories/`,
		`euvd\.enisa\.europa\.eu/`,
		`advisories\.gitlab\.com/`,
		`kb\.cert\.org/vuls/`,
		`jvn\.jp/`,
		`vuldb\.com/\?id\.`,
		`wpscan\.com/vulnerability/`,
		`https?://[^\s"'<>]*/(?:[a-z0-9_-]*advisor(?:y|ies)|[a-z0-9_-]*security[-_]?bulletins?|psirt)\b`),
}

// checkAdvisoryKeys runs check 14 over every file under signatures/ and
// tests/fixtures/ and returns one message per key found.
func checkAdvisoryKeys(root string) []string {
	var errs []string
	read := 0
	for _, dir := range []string{signaturesDir, fixturesDir} {
		var files []string
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(dir)), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", dir, pathErrorCause(err)))
		}
		sort.Strings(files)
		for _, p := range files {
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			b, err := os.ReadFile(p)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", redactAdvisoryKeys(rel), pathErrorCause(err)))
				continue
			}
			read++
			errs = append(errs, advisoryFindings(rel, b)...)
		}
	}
	if read == 0 {
		errs = append(errs, fmt.Sprintf("read no file under %s/ or %s/", signaturesDir, fixturesDir))
	}
	return errs
}

// advisoryScalar is a key or a string value of a YAML or JSON document, as
// decoded, with the line it starts on.
type advisoryScalar struct {
	line  int
	where string // "field <path>" or "key <path>"
	value string
}

// advisoryFindings returns one message per advisory key in one file, in line
// order after any key in the file's path. A key in a decoded value is
// reported with its field, on each line as written that carries it, or on the
// line the value starts on when no line as written does (an escaped key). A
// key in a line as written that no decoded value on that line, or in the
// value the line continues, explains is reported as the line: a comment, or a
// file that is not YAML or JSON.
func advisoryFindings(rel string, b []byte) []string {
	scalars := advisoryScalars(rel, b)
	sort.SliceStable(scalars, func(i, k int) bool { return scalars[i].line < scalars[k].line })

	type hit struct{ scalar, rule int }
	decoded := map[hit]bool{}
	var hits []hit
	for si, s := range scalars {
		for ri, r := range advisoryRules {
			if r.re.MatchString(s.value) {
				decoded[hit{si, ri}] = true
				hits = append(hits, hit{si, ri})
			}
		}
	}

	type finding struct {
		line, rule int // line 0 is the file's path
		where      string
	}
	var findings []finding
	for ri, r := range advisoryRules {
		if r.re.MatchString(rel) {
			findings = append(findings, finding{0, ri, "the path"})
		}
	}
	written := map[hit][]int{}
	for i, text := range bytes.Split(b, []byte("\n")) {
		line := i + 1
		// The values that start on this line, or else the last value that
		// starts before it, which a multi-line value continues onto it.
		lo := sort.Search(len(scalars), func(k int) bool { return scalars[k].line >= line })
		hi := lo
		for hi < len(scalars) && scalars[hi].line == line {
			hi++
		}
		if lo == hi && lo > 0 {
			lo--
		}
		for ri, r := range advisoryRules {
			if !r.re.Match(text) {
				continue
			}
			explained := false
			for si := lo; si < hi; si++ {
				if h := (hit{si, ri}); decoded[h] {
					written[h] = append(written[h], line)
					explained = true
				}
			}
			if !explained {
				findings = append(findings, finding{line, ri, "the line"})
			}
		}
	}
	for _, h := range hits {
		lines := written[h]
		if len(lines) == 0 {
			lines = []int{scalars[h.scalar].line}
		}
		for _, line := range lines {
			findings = append(findings, finding{line, h.rule, scalars[h.scalar].where})
		}
	}
	sort.SliceStable(findings, func(i, k int) bool {
		if findings[i].line != findings[k].line {
			return findings[i].line < findings[k].line
		}
		return findings[i].rule < findings[k].rule
	})
	file := redactAdvisoryKeys(rel)
	msgs := make([]string, 0, len(findings))
	for _, f := range findings {
		at := file
		if f.line > 0 {
			at = fmt.Sprintf("%s:%d", file, f.line)
		}
		msgs = append(msgs, fmt.Sprintf("%s: %s carries %s; %s", at, redactAdvisoryKeys(f.where), advisoryRules[f.rule].kind, advisoryRuleText))
	}
	return msgs
}

// redactAdvisoryKeys replaces every advisory key in s with advisoryKeyMark.
func redactAdvisoryKeys(s string) string {
	for _, r := range advisoryRules {
		s = r.re.ReplaceAllLiteralString(s, advisoryKeyMark)
	}
	return s
}

// pathErrorCause drops the path a file system error repeats; the caller
// prints the path, with any key in it replaced.
func pathErrorCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// advisoryScalars lists the keys and string values of a YAML or JSON file.
// A file of another kind lists none, and a document that stops parsing lists
// what was read before it stopped; check 1 and check 9 report such errors,
// and the lines as written are read either way.
func advisoryScalars(rel string, b []byte) []advisoryScalar {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".yaml", ".yml":
		return yamlAdvisoryScalars(b)
	case ".json":
		return jsonAdvisoryScalars(b)
	}
	return nil
}

func yamlAdvisoryScalars(b []byte) []advisoryScalar {
	var out []advisoryScalar
	var walk func(n *yaml.Node, path string)
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				p := joinFieldPath(path, k.Value)
				out = append(out, advisoryScalar{k.Line, "key " + p, k.Value})
				walk(n.Content[i+1], p)
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, fmt.Sprintf("%s[%d]", path, i))
			}
		case yaml.ScalarNode:
			out = append(out, advisoryScalar{n.Line, fieldLabel(path), n.Value})
		}
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return out
		}
		walk(&doc, "")
	}
}

// jsonAdvisoryScalars reads a JSON document token by token, so a string is
// decoded the way encoding/json decodes it and keeps its line. An array named
// codepoints is also listed as the text its hex codepoints spell, the way
// check 10 reads a fixture case.
func jsonAdvisoryScalars(b []byte) []advisoryScalar {
	type frame struct {
		path    string
		line    int
		object  bool
		wantKey bool     // object: the next token is a key
		key     string   // object: the key of the next value
		next    int      // array: the index of the next element
		strs    []string // array: its string elements
		other   bool     // array: holds an element that is not a string
	}
	var (
		out   []advisoryScalar
		stack []*frame
		line  = 1
		off   int64
	)
	dec := json.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		// A JSON token never spans lines, so the line its end is on is
		// the line it starts on.
		end := dec.InputOffset()
		line += bytes.Count(b[off:end], []byte("\n"))
		off = end
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			if top == nil {
				return out
			}
			stack = stack[:len(stack)-1]
			if d == ']' && !top.other && len(top.strs) > 0 && (top.path == "codepoints" || strings.HasSuffix(top.path, ".codepoints")) {
				if text, err := caseText(FixtureCase{Codepoints: top.strs}); err == nil {
					out = append(out, advisoryScalar{top.line, fieldLabel(top.path) + " (decoded)", text})
				}
			}
			continue
		}
		if top != nil && top.object && top.wantKey {
			k, _ := tok.(string)
			top.key, top.wantKey = k, false
			out = append(out, advisoryScalar{line, "key " + joinFieldPath(top.path, k), k})
			continue
		}
		path := ""
		if top != nil {
			if top.object {
				path, top.wantKey = joinFieldPath(top.path, top.key), true
			} else {
				path = fmt.Sprintf("%s[%d]", top.path, top.next)
				top.next++
			}
		}
		switch v := tok.(type) {
		case json.Delim:
			if top != nil && !top.object {
				top.other = true
			}
			stack = append(stack, &frame{path: path, line: line, object: v == '{', wantKey: v == '{'})
		case string:
			out = append(out, advisoryScalar{line, fieldLabel(path), v})
			if top != nil && !top.object {
				top.strs = append(top.strs, v)
			}
		default:
			if top != nil && !top.object {
				top.other = true
			}
		}
	}
}

// joinFieldPath appends a mapping key to a field path.
func joinFieldPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// fieldLabel names the value at path in a failure.
func fieldLabel(path string) string {
	if path == "" {
		return "the document"
	}
	return "field " + path
}

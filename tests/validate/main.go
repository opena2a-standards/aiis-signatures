// Command aiis-validate is a self-contained gate for this repo. It has no
// external dependencies (stdlib only) so it runs on a bare Go toolchain in CI
// without network access.
//
// It (1) compiles every signature's `pattern` with Go's regexp (RE2 — the same
// engine the HoneyMap reference matcher uses), catching a malformed pattern
// before HoneyMap ever consumes it, and (2) runs the shouldMatch / shouldNotMatch
// fixtures for the plain-regex hidden-text signatures against the compiled
// pattern, catching a detection regression in the public repo itself.
//
// Codepoint-based fixtures (AIIS-UNICODE-TAG-BLOCK-01) require the flag-strip
// matcher logic that lives in HoneyMap; their behavioural assertion is covered
// by HoneyMap's TestSeedSignatureFixtures. Here we only validate that such
// fixtures parse. Run from tests/validate/: `go run .`.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// patternLine extracts the single-quoted value of a `pattern:` YAML key without
// a full YAML parser. Signature patterns are always a single single-quoted
// scalar on one line; YAML escapes an embedded quote as '' (none today).
var patternLine = regexp.MustCompile(`^\s*pattern:\s*'(.*)'\s*$`)
var idLine = regexp.MustCompile(`^id:\s*(\S+)`)

type fixture struct {
	Signature      string `json:"signature"`
	ShouldMatch    []fixtureCase
	ShouldNotMatch []fixtureCase
}
type fixtureCase struct {
	Name       string   `json:"name"`
	Text       string   `json:"text"`
	Codepoints []string `json:"codepoints"`
}

func main() {
	failures := 0
	compiled := map[string]*regexp.Regexp{} // signature id -> pattern

	// 1. Compile every signature pattern.
	sigFiles, _ := filepath.Glob("../../signatures/*/*.yaml")
	for _, f := range sigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("FAIL read %s: %v\n", f, err)
			failures++
			continue
		}
		var id, pat string
		for _, line := range strings.Split(string(b), "\n") {
			if m := idLine.FindStringSubmatch(line); m != nil && id == "" {
				id = m[1]
			}
			if m := patternLine.FindStringSubmatch(line); m != nil && pat == "" {
				pat = strings.ReplaceAll(m[1], "''", "'")
			}
		}
		if pat == "" {
			// Not every signature is a single-line regex (e.g. unicode_range
			// matchers declare ranges, not a pattern). Skip silently.
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			fmt.Printf("FAIL compile %s (%s): %v\n", id, filepath.Base(f), err)
			failures++
			continue
		}
		compiled[id] = re
		fmt.Printf("ok   compile %s\n", id)
	}

	// 2. Run plain-text fixtures against the compiled pattern.
	fixFiles, _ := filepath.Glob("../../tests/fixtures/*.json")
	for _, f := range fixFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("FAIL read %s: %v\n", f, err)
			failures++
			continue
		}
		var fx fixture
		if err := json.Unmarshal(b, &fx); err != nil {
			fmt.Printf("FAIL json %s: %v\n", filepath.Base(f), err)
			failures++
			continue
		}
		re := compiled[fx.Signature]
		if re == nil {
			continue // pattern-less signature (e.g. unicode_range) — parse-only
		}
		check := func(cases []fixtureCase, want bool) {
			for _, c := range cases {
				if len(c.Codepoints) > 0 {
					continue // codepoint fixtures validated by the honeymap matcher
				}
				if re.MatchString(c.Text) != want {
					verb := "should MATCH"
					if !want {
						verb = "should NOT match"
					}
					fmt.Printf("FAIL fixture %s/%s: %q %s\n", fx.Signature, c.Name, c.Text, verb)
					failures++
				}
			}
		}
		check(fx.ShouldMatch, true)
		check(fx.ShouldNotMatch, false)
		fmt.Printf("ok   fixtures %s\n", fx.Signature)
	}

	if failures > 0 {
		fmt.Printf("\n%d failure(s)\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall signatures compile; all plain-text fixtures pass")
}

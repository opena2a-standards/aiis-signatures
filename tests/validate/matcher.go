package main

import (
	"fmt"
	"regexp"
	"strings"
)

// MatchSpec is the `match` block of a signature, decoded from YAML. The
// four types are regex, substring, unicode_range and composite; composite
// recurses through all_of and any_of.
type MatchSpec struct {
	Type                 string         `json:"type"`
	Pattern              string         `json:"pattern"`
	Flags                string         `json:"flags"`
	Contains             []string       `json:"contains"`
	CaseSensitive        bool           `json:"case_sensitive"`
	Ranges               []UnicodeRange `json:"ranges"`
	MinMatches           int            `json:"min_matches"`
	ExcludeEmojiTagFlags bool           `json:"exclude_emoji_tag_flags"`
	AllOf                []MatchSpec    `json:"all_of"`
	AnyOf                []MatchSpec    `json:"any_of"`
}

// UnicodeRange is one inclusive codepoint range, each endpoint a single rune.
type UnicodeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Matcher evaluates one document and reports whether the signature fires.
type Matcher interface {
	Match(doc string) bool
}

// compileMatch turns a MatchSpec into a Matcher, or reports why it cannot.
func compileMatch(spec MatchSpec) (Matcher, error) {
	switch spec.Type {
	case "regex":
		if spec.Pattern == "" {
			return nil, fmt.Errorf("regex match requires pattern")
		}
		pat := spec.Pattern
		if spec.Flags != "" {
			pat = "(?" + spec.Flags + ")" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("regex %q: %w", spec.Pattern, err)
		}
		return regexMatcher{re: re}, nil
	case "substring":
		if len(spec.Contains) == 0 {
			return nil, fmt.Errorf("substring match requires contains")
		}
		m := substringMatcher{caseSensitive: spec.CaseSensitive}
		for _, n := range spec.Contains {
			if !spec.CaseSensitive {
				n = strings.ToLower(n)
			}
			m.needles = append(m.needles, n)
		}
		return m, nil
	case "unicode_range":
		if len(spec.Ranges) == 0 {
			return nil, fmt.Errorf("unicode_range match requires ranges")
		}
		m := unicodeRangeMatcher{min: spec.MinMatches, excludeFlags: spec.ExcludeEmojiTagFlags}
		if m.min < 1 {
			m.min = 1
		}
		for _, r := range spec.Ranges {
			from, to := []rune(r.From), []rune(r.To)
			if len(from) != 1 || len(to) != 1 {
				return nil, fmt.Errorf("unicode_range endpoints must be single codepoints: from=%q to=%q", r.From, r.To)
			}
			if from[0] > to[0] {
				return nil, fmt.Errorf("unicode_range from U+%04X is above to U+%04X", from[0], to[0])
			}
			m.ranges = append(m.ranges, [2]rune{from[0], to[0]})
		}
		return m, nil
	case "composite":
		if len(spec.AllOf) == 0 && len(spec.AnyOf) == 0 {
			return nil, fmt.Errorf("composite match requires all_of or any_of")
		}
		m := compositeMatcher{}
		for i, sub := range spec.AllOf {
			c, err := compileMatch(sub)
			if err != nil {
				return nil, fmt.Errorf("all_of[%d]: %w", i, err)
			}
			m.allOf = append(m.allOf, c)
		}
		for i, sub := range spec.AnyOf {
			c, err := compileMatch(sub)
			if err != nil {
				return nil, fmt.Errorf("any_of[%d]: %w", i, err)
			}
			m.anyOf = append(m.anyOf, c)
		}
		return m, nil
	}
	return nil, fmt.Errorf("unknown match type %q", spec.Type)
}

type regexMatcher struct{ re *regexp.Regexp }

func (m regexMatcher) Match(doc string) bool { return m.re.MatchString(doc) }

type substringMatcher struct {
	needles       []string
	caseSensitive bool
}

// Match fires when any needle occurs in the document. case_sensitive
// defaults to false, in which case both sides are lower-cased.
func (m substringMatcher) Match(doc string) bool {
	hay := doc
	if !m.caseSensitive {
		hay = strings.ToLower(doc)
	}
	for _, n := range m.needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

type unicodeRangeMatcher struct {
	ranges       [][2]rune
	min          int
	excludeFlags bool
}

// Emoji tag sequence flags: a U+1F3F4 base, one or more Tag characters in
// U+E0020 to U+E007E, and the U+E007F terminator. The three RGI flags
// (England, Scotland, Wales) are the only such sequences sanctioned for
// general interchange and the one legitimate use of the Tag block on the
// open web. Only those are stripped: a sequence with another body or no
// terminator is a payload wearing a flag wrapper and stays counted.
const (
	flagBase      rune = 0x1F3F4
	tagLow        rune = 0xE0020
	tagHigh       rune = 0xE007E
	tagTerminator rune = 0xE007F
	tagToASCII    rune = 0xE0000
)

var rgiFlagBodies = map[string]bool{"gbeng": true, "gbsct": true, "gbwls": true}

func stripEmojiTagFlags(doc string) string {
	if !strings.ContainsRune(doc, flagBase) {
		return doc
	}
	runes := []rune(doc)
	out := make([]rune, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		if runes[i] == flagBase {
			j := i + 1
			var body []byte
			for j < len(runes) && runes[j] >= tagLow && runes[j] <= tagHigh {
				body = append(body, byte(runes[j]-tagToASCII))
				j++
			}
			if j > i+1 && j < len(runes) && runes[j] == tagTerminator && rgiFlagBodies[string(body)] {
				i = j
				continue
			}
		}
		out = append(out, runes[i])
	}
	return string(out)
}

// Match counts codepoints inside any range and fires at min_matches.
func (m unicodeRangeMatcher) Match(doc string) bool {
	if m.excludeFlags {
		doc = stripEmojiTagFlags(doc)
	}
	count := 0
	for _, r := range doc {
		for _, pair := range m.ranges {
			if r >= pair[0] && r <= pair[1] {
				count++
				break
			}
		}
		if count >= m.min {
			return true
		}
	}
	return false
}

type compositeMatcher struct {
	allOf []Matcher
	anyOf []Matcher
}

// Match requires every all_of member and, when any_of is present, at least
// one any_of member.
func (m compositeMatcher) Match(doc string) bool {
	for _, sub := range m.allOf {
		if !sub.Match(doc) {
			return false
		}
	}
	if len(m.anyOf) == 0 {
		return true
	}
	for _, sub := range m.anyOf {
		if sub.Match(doc) {
			return true
		}
	}
	return false
}

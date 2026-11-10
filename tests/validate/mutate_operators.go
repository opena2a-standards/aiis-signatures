package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The operators of the evasion bench (mutate.go). Each is deterministic,
// keeps the label of the case it transforms, and has its exact inverse in
// this file: for a case that does not already carry a code point the inverse
// rewrites, inverse(apply(text)) == text byte for byte. A mutant is always a
// transform of a fixture case, never a new text: no paraphrase, synonym,
// translation or generated text.

// operator is one evasion transform.
type operator struct {
	name    string
	about   string
	apply   func(string) string
	inverse func(string) string
	// emits lists, as inclusive ranges, the code points apply writes in
	// place of its input. The bench does not apply an operator to a
	// signature whose own unicode_range contains one of them: the mutant
	// would carry the feature the signature detects.
	emits [][2]rune
}

// benchOperators returns the operators of this slice in table order.
func benchOperators() []operator {
	return []operator{
		{
			name:    "zero-width",
			about:   "U+200B after every letter",
			apply:   zeroWidthInterleave,
			inverse: zeroWidthRemove,
			emits:   [][2]rune{{zeroWidthSpace, zeroWidthSpace}},
		},
		{
			name:    "fullwidth",
			about:   "U+0021..U+007E moved to U+FF01..U+FF5E",
			apply:   toFullwidth,
			inverse: fromFullwidth,
			emits:   [][2]rune{{asciiFirst + fullwidthOffset, asciiLast + fullwidthOffset}},
		},
		{
			name:    "confusables",
			about:   fmt.Sprintf("%d Latin letters to Cyrillic or Greek look-alikes", len(confusablePairs)),
			apply:   toConfusables,
			inverse: fromConfusables,
			emits:   confusableEmits(),
		},
	}
}

// rewriteRunes rebuilds s rune by rune. f receives each rune with its own
// bytes and writes the replacement. A byte that is not valid UTF-8 arrives as
// utf8.RuneError with that single byte, so a transform that copies raw for a
// rune it does not target keeps every other byte of its input.
func rewriteRunes(s string, f func(b *strings.Builder, r rune, raw string)) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/2)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		f(&b, r, s[i:i+size])
		i += size
	}
	return b.String()
}

// (a) Zero-width interleave.

const (
	zeroWidthSpace     rune = '\u200B' // ZERO WIDTH SPACE
	zeroWidthNonJoiner rune = '\u200C' // ZERO WIDTH NON-JOINER
	zeroWidthJoiner    rune = '\u200D' // ZERO WIDTH JOINER
	wordJoiner         rune = '\u2060' // WORD JOINER
)

// zeroWidthInterleave writes U+200B after every letter.
func zeroWidthInterleave(s string) string {
	return rewriteRunes(s, func(b *strings.Builder, r rune, raw string) {
		b.WriteString(raw)
		if unicode.IsLetter(r) {
			b.WriteRune(zeroWidthSpace)
		}
	})
}

// zeroWidthRemove is the inverse: it deletes U+200B, U+200C, U+200D and
// U+2060.
func zeroWidthRemove(s string) string {
	return rewriteRunes(s, func(b *strings.Builder, r rune, raw string) {
		switch r {
		case zeroWidthSpace, zeroWidthNonJoiner, zeroWidthJoiner, wordJoiner:
			return
		}
		b.WriteString(raw)
	})
}

// (b) Fullwidth.

const (
	asciiFirst      rune = '\u0021' // EXCLAMATION MARK
	asciiLast       rune = '\u007E' // TILDE
	fullwidthOffset rune = 0xFEE0   // U+FF01 FULLWIDTH EXCLAMATION MARK minus U+0021
)

// toFullwidth moves ASCII U+0021..U+007E to U+FF01..U+FF5E.
func toFullwidth(s string) string {
	return rewriteRunes(s, func(b *strings.Builder, r rune, raw string) {
		if r >= asciiFirst && r <= asciiLast {
			b.WriteRune(r + fullwidthOffset)
			return
		}
		b.WriteString(raw)
	})
}

// fromFullwidth is the inverse: it subtracts the offset from U+FF01..U+FF5E.
func fromFullwidth(s string) string {
	return rewriteRunes(s, func(b *strings.Builder, r rune, raw string) {
		if r >= asciiFirst+fullwidthOffset && r <= asciiLast+fullwidthOffset {
			b.WriteRune(r - fullwidthOffset)
			return
		}
		b.WriteString(raw)
	})
}

// (c) Confusables.

// confusablePairs maps a Latin letter to a Cyrillic or Greek letter drawn the
// same in common fonts. The table is one to one, so the reversed table is
// the exact inverse.
var confusablePairs = []struct{ latin, lookalike rune }{
	{'\u0041', '\u0410'}, // LATIN CAPITAL LETTER A -> CYRILLIC CAPITAL LETTER A
	{'\u0042', '\u0412'}, // LATIN CAPITAL LETTER B -> CYRILLIC CAPITAL LETTER VE
	{'\u0043', '\u0421'}, // LATIN CAPITAL LETTER C -> CYRILLIC CAPITAL LETTER ES
	{'\u0045', '\u0415'}, // LATIN CAPITAL LETTER E -> CYRILLIC CAPITAL LETTER IE
	{'\u0048', '\u041D'}, // LATIN CAPITAL LETTER H -> CYRILLIC CAPITAL LETTER EN
	{'\u0049', '\u0406'}, // LATIN CAPITAL LETTER I -> CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
	{'\u004A', '\u0408'}, // LATIN CAPITAL LETTER J -> CYRILLIC CAPITAL LETTER JE
	{'\u004B', '\u041A'}, // LATIN CAPITAL LETTER K -> CYRILLIC CAPITAL LETTER KA
	{'\u004D', '\u041C'}, // LATIN CAPITAL LETTER M -> CYRILLIC CAPITAL LETTER EM
	{'\u004E', '\u039D'}, // LATIN CAPITAL LETTER N -> GREEK CAPITAL LETTER NU
	{'\u004F', '\u041E'}, // LATIN CAPITAL LETTER O -> CYRILLIC CAPITAL LETTER O
	{'\u0050', '\u0420'}, // LATIN CAPITAL LETTER P -> CYRILLIC CAPITAL LETTER ER
	{'\u0053', '\u0405'}, // LATIN CAPITAL LETTER S -> CYRILLIC CAPITAL LETTER DZE
	{'\u0054', '\u0422'}, // LATIN CAPITAL LETTER T -> CYRILLIC CAPITAL LETTER TE
	{'\u0058', '\u0425'}, // LATIN CAPITAL LETTER X -> CYRILLIC CAPITAL LETTER HA
	{'\u0059', '\u04AE'}, // LATIN CAPITAL LETTER Y -> CYRILLIC CAPITAL LETTER STRAIGHT U
	{'\u005A', '\u0396'}, // LATIN CAPITAL LETTER Z -> GREEK CAPITAL LETTER ZETA
	{'\u0061', '\u0430'}, // LATIN SMALL LETTER A -> CYRILLIC SMALL LETTER A
	{'\u0063', '\u0441'}, // LATIN SMALL LETTER C -> CYRILLIC SMALL LETTER ES
	{'\u0064', '\u0501'}, // LATIN SMALL LETTER D -> CYRILLIC SMALL LETTER KOMI DE
	{'\u0065', '\u0435'}, // LATIN SMALL LETTER E -> CYRILLIC SMALL LETTER IE
	{'\u0068', '\u04BB'}, // LATIN SMALL LETTER H -> CYRILLIC SMALL LETTER SHHA
	{'\u0069', '\u0456'}, // LATIN SMALL LETTER I -> CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
	{'\u006A', '\u0458'}, // LATIN SMALL LETTER J -> CYRILLIC SMALL LETTER JE
	{'\u006F', '\u043E'}, // LATIN SMALL LETTER O -> CYRILLIC SMALL LETTER O
	{'\u0070', '\u0440'}, // LATIN SMALL LETTER P -> CYRILLIC SMALL LETTER ER
	{'\u0071', '\u051B'}, // LATIN SMALL LETTER Q -> CYRILLIC SMALL LETTER QA
	{'\u0073', '\u0455'}, // LATIN SMALL LETTER S -> CYRILLIC SMALL LETTER DZE
	{'\u0077', '\u051D'}, // LATIN SMALL LETTER W -> CYRILLIC SMALL LETTER WE
	{'\u0078', '\u0445'}, // LATIN SMALL LETTER X -> CYRILLIC SMALL LETTER HA
	{'\u0079', '\u0443'}, // LATIN SMALL LETTER Y -> CYRILLIC SMALL LETTER U
}

// confusableTo is the table, confusableFrom its reverse.
var confusableTo, confusableFrom = confusableMaps()

func confusableMaps() (to, from map[rune]rune) {
	to = make(map[rune]rune, len(confusablePairs))
	from = make(map[rune]rune, len(confusablePairs))
	for _, p := range confusablePairs {
		to[p.latin] = p.lookalike
		from[p.lookalike] = p.latin
	}
	return to, from
}

// confusableEmits lists every look-alike as a one code point range,
// ascending.
func confusableEmits() [][2]rune {
	out := make([][2]rune, 0, len(confusablePairs))
	for _, p := range confusablePairs {
		out = append(out, [2]rune{p.lookalike, p.lookalike})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// toConfusables writes each Latin letter of the table as its look-alike.
func toConfusables(s string) string { return swapRunes(s, confusableTo) }

// fromConfusables is the inverse: it writes each look-alike as its Latin
// letter.
func fromConfusables(s string) string { return swapRunes(s, confusableFrom) }

func swapRunes(s string, table map[rune]rune) string {
	return rewriteRunes(s, func(b *strings.Builder, r rune, raw string) {
		if v, ok := table[r]; ok {
			b.WriteRune(v)
			return
		}
		b.WriteString(raw)
	})
}

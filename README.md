# AIIS Signatures

**AI Injection Signature Standard** — an open, YARA-style detection format for AI agent prompt injections embedded in web content.

AIIS is the public counterpart of the OpenA2A HoneyMap scanner and is published here under Apache License 2.0. Anyone can read, reuse, extend, or contribute signatures. The goal is to establish an interoperable detection standard the same way YARA did for malware.

## What AIIS signatures detect

Prompt injections, jailbreaks, exfiltration instructions, and steganographic payloads hidden in:

- Hidden / invisible text (`display:none`, `visibility:hidden`, 1px text, off-screen)
- HTML comments
- HTML attributes (`alt`, `title`, `aria-*`, `data-*`, custom attributes)
- Script string literals
- Meta tags and Open Graph metadata
- JSON-LD structured data
- `robots.txt` / `llms.txt` overrides
- HTTP response headers
- `noscript` / `iframe srcdoc` fallback content
- Inline styles with embedded instructions

## Schema

Each signature is a JSON/YAML file under `signatures/<category>/` conforming to `schema/aiis-v0.1.schema.json`.

```yaml
id: AIIS-PROMPT-ROLE-INJECT-01
name: Role injection via hidden-text system marker
version: 0.1.0
severity: high
attack_class: SOUL-INJECT
technique_ids: [T-2001]
surface_types: [hidden_text, html_comment, alt_aria]
match:
  type: regex
  pattern: '(?i)\\[?\\s*(SYSTEM|ADMIN|INST|\\|system\\|)\\s*\\]?.{0,200}(ignore|override|disregard|forget|reveal)'
cwe_ids: [CWE-74]
references:
  - https://arxiv.org/abs/2306.05499
  - opena2a.org/research/aiis
false_positive_notes: >
  May fire on security research articles that quote injection samples. Pair with
  domain context (not a known research/docs domain) for production use.
```

## Repository layout

```
signatures/                  # YAML signature files grouped by surface category
  hidden-text/
  html-attr/
  script-literal/
  meta-tag/
  ...
schema/
  aiis-v0.1.schema.json      # canonical JSON Schema for signatures
tests/
  fixtures/                  # positive and negative match examples
examples/                    # worked examples for contributors
```

## Using AIIS signatures

- **OpenA2A HoneyMap** consumes these signatures as its Phase 1 classifier tier.
- **HMA (HackMyAgent)** uses AIIS-derived check IDs (`AI-WILD-*`) for static scans.
- **DVAA** uses AIIS-derived attack scenarios for lab reproduction.
- **Any third-party scanner** can implement the schema and reuse the signature pack.

## Contributing

Contributions welcome. See `CONTRIBUTING.md` (coming soon) for the review process. The signature corpus is intentionally conservative — we prefer to ship high-precision, low-false-positive patterns over coverage.

## License

Apache License 2.0. See `LICENSE`.

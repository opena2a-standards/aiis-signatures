# AIIS Signatures

**AI Injection and Infrastructure Signature Standard** — an open, YARA-style detection format for AI agent prompt injections and public AI-agent infrastructure exposure.

AIIS is the public counterpart of the OpenA2A HoneyMap scanner and is published here under Apache License 2.0. Anyone can read, reuse, extend, or contribute signatures. The goal is to establish an interoperable detection standard the same way YARA did for malware.

## Two signature categories

Each signature declares a `category`:

- **`injection`** (default) — matches prompt-injection artefacts embedded in public content: hidden text, HTML comments, script literals, meta tags, attributes, and so on. Detects the *attack payload*.
- **`exposure`** — matches evidence that a host publicly exposes an AI-agent component: MCP servers, LLM gateways, self-hosted LLM UIs, agent frameworks, RAG services, AI copilots, vector databases, tool registries, unauthenticated admin endpoints, and known-vulnerable version strings. Detects the *attack surface*, not a specific attack.

Older signatures without an explicit `category` field are treated as `injection`.

## What AIIS signatures detect

### Injection category

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

### Exposure category

Fingerprints of publicly-reachable AI infrastructure:

- MCP server banners and JSON-RPC response shapes (`EXPOSURE-MCP-SERVER`)
- LLM gateways: LiteLLM, OpenRouter-style proxies (`EXPOSURE-LLM-GATEWAY`)
- Self-hosted LLM servers: Ollama, llama.cpp, vLLM, LocalAI, Text Generation WebUI (`EXPOSURE-SELFHOSTED-LLM`)
- Agent frameworks: LangServe, AutoGen, CrewAI, LlamaIndex (`EXPOSURE-AGENT-FRAMEWORK`)
- RAG services: Haystack, RAGFlow, LlamaIndex query endpoints (`EXPOSURE-RAG-SERVICE`)
- AI copilots: self-hosted Copilot-style proxies (`EXPOSURE-AI-COPILOT`)
- Vector databases: Chroma, Qdrant, Milvus, Weaviate (`EXPOSURE-VECTOR-DB`)
- Tool registries and MCP catalogues (`EXPOSURE-TOOL-REGISTRY`)
- Any of the above reachable without auth or with default credentials (`EXPOSURE-AUTH-MISCONFIG`)
- Running versions with published CVEs (`EXPOSURE-VERSION-DRIFT`)

## Schema

Each signature is a JSON/YAML file under `signatures/<category>/` conforming to `schema/aiis-v0.1.schema.json`.

```yaml
id: AIIS-PROMPT-ROLE-INJECT-01
category: injection
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

An exposure-category signature example:

```yaml
id: AIIS-EXPOSURE-OLLAMA-TAGS-01
category: exposure
name: Exposed Ollama model listing
version: 0.1.0
severity: medium
attack_class: EXPOSURE-SELFHOSTED-LLM
technique_ids: [T-1001]
surface_types: [http_body]
match:
  type: composite
  all_of:
    - { type: substring, contains: ["\"models\":"] }
    - { type: regex, pattern: '"modified_at"\s*:\s*"[0-9]{4}-[0-9]{2}-[0-9]{2}' }
status: draft
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

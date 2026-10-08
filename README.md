# AIIS Signatures

**AI Injection and Infrastructure Signature Standard** — an open, YARA-style detection format for AI agent prompt injections and public AI-agent infrastructure exposure.

AIIS is the public counterpart of the OpenA2A HoneyMap scanner and is published here under Apache License 2.0. Anyone can read, reuse, extend, or contribute signatures. The goal is an interoperable detection standard, the way YARA became one for malware.

## Use cases

### A web page tells your agent what to do, and every scanner spells the rule differently

A page carries an instruction in hidden text, an HTML comment, a meta tag or a tool description. The agent reading it cannot tell that text from its task. Each scanner that looks for this writes its own private rules, so nothing can be shared or compared, and a site owner has no common rule set to test their own pages against.

AIIS is a YAML signature format, in the spirit of YARA, evaluated against one document. An injection signature detects the payload and carries the Agent Threat Matrix attack vector and canonical attack class, and every signature ships with fixture cases that must match and must not match.

What you can do today: run the validator, which checks every signature and every fixture case offline.

```
git clone https://github.com/opena2a-standards/aiis-signatures
cd aiis-signatures/tests/validate
go run -mod=vendor .
```

Where it stops today: a signature judges one document. Behaviour that can be judged across a session, such as what an agent did in which order, is out of scope for this format. No signature yet targets tool descriptions: the schema accepts `tool_description` as a surface type, but no shipped signature declares it.

### Your MCP server is on the public internet and you did not know

Teams stand up MCP servers, LLM gateways, self-hosted inference servers and vector databases, and some end up reachable from the internet.

Exposure signatures fingerprint publicly reachable AI infrastructure and carry an exposure class, so a scanner can tell an operator what is exposed, not just that something answered.

What you can do today: read the signatures under `signatures/exposure/` and the class list in `schema/exposure-classes.json`, and run the validator above.

Where it stops today: three exposure classes (RAG service, AI copilot, tool registry) are reserved as valid values with no signature yet.

Why you can check this yourself: the schema is [`schema/aiis-v0.2.schema.json`](schema/aiis-v0.2.schema.json); the signatures are under [`signatures/`](signatures/) with one fixture file per signature in [`tests/fixtures/`](tests/fixtures/); the validator in [`tests/validate/`](tests/validate/) runs thirteen checks with vendored dependencies and no network; [`CHANGELOG.md`](CHANGELOG.md) records the current corpus release; and the matrix the signatures cite is pinned under [`vendor/agent-threat-matrix/`](vendor/agent-threat-matrix/).

## Scope

A signature is evaluated against one document: a page, a header set, a response body, a tool description, a governance file. Behaviour that can only be judged across a session or from telemetry (what an agent did, in which order, with which tool results) is out of scope for this format; behavioural formats are a sibling specification.

## Two signature categories

Every signature declares a `category`, and the category selects which classification fields it must carry:

- **`injection`** matches a prompt injection artefact embedded in a document: hidden text, HTML comments, script literals, meta tags, attributes, headers, tool descriptions. It detects the attack payload and carries a matrix `attack_vector` and a canonical `attack_class`.
- **`exposure`** matches evidence that a host publicly exposes an AI component: an MCP server, an LLM gateway, a self-hosted inference server, an agent framework, a vector database. It detects the attack surface, not a specific attack, and carries an `exposure_class`.

There is no default category in schema 0.2.

## What AIIS signatures detect

### Injection category

Prompt injections, jailbreaks, exfiltration instructions, and steganographic payloads hidden in:

- Hidden or invisible text (`display:none`, `visibility:hidden`, 1px text, off-screen)
- HTML comments
- HTML attributes (`alt`, `title`, `aria-*`, `data-*`, custom attributes)
- Script string literals
- Meta tags and Open Graph metadata
- JSON-LD structured data
- `robots.txt` and `llms.txt` overrides
- HTTP response headers
- `noscript` and `iframe srcdoc` fallback content
- Inline styles with embedded instructions
- Tool descriptions, tool results and tool errors
- Governance files, memory entries and skill frontmatter

### Exposure category

Fingerprints of publicly reachable AI infrastructure, one `exposure_class` each (`schema/exposure-classes.json`):

- `EXPOSURE-MCP-SERVER`: MCP server JSON-RPC response shapes
- `EXPOSURE-LLM-GATEWAY`: LLM gateways such as LiteLLM
- `EXPOSURE-SELFHOSTED-LLM`: Ollama, vLLM, llama.cpp, LocalAI
- `EXPOSURE-AGENT-FRAMEWORK`: LangServe, AutoGen, CrewAI
- `EXPOSURE-VECTOR-DB`: Chroma, Qdrant, Milvus, Weaviate
- `EXPOSURE-RAG-SERVICE`, `EXPOSURE-AI-COPILOT`, `EXPOSURE-TOOL-REGISTRY`: reserved, valid values with no signature yet

## Schema

Each signature is a YAML file at `signatures/<family>/<id>.yaml` conforming to `schema/aiis-v0.2.schema.json` (JSON Schema draft 2020-12). Schema 0.1 stays in the repository for readers of the earlier releases and is not used by the validator.

Fields common to both categories:

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | the constant `"0.2"` |
| `id` | yes | `AIIS-<FAMILY>-<NAME>-<NN>`; the family token is registered in `schema/families.json` and the file lives in `signatures/<family lowercased>/` |
| `name`, `version`, `severity`, `status` | yes | as before; `status` is `draft` or `active`, and a retired signature is deleted and recorded in `retired-ids.yaml` |
| `category` | yes | `injection` or `exposure` |
| `technique_id` | yes | the primary Agent Threat Matrix technique, resolved against the vendored `matrix.json` |
| `related_technique_ids` | no | further techniques the same payload evidences; never repeats the primary |
| `surface_types` | yes | where the document came from; schema 0.2 adds `tool_description`, `tool_result`, `tool_error`, `governance_file`, `memory_entry`, `skill_frontmatter` |
| `match` | yes | `regex`, `substring`, `unicode_range` or `composite` (`all_of` and `any_of`, recursive) |
| `provenance` | when active | `evidence_tier` (`observed`, `validated`, `adapted`), optional `source` and `first_seen` |
| `hma_check_ids` | no | the HackMyAgent check from its own taxonomy that detects the same payload family on local agent files; empty where none exists |
| `cwe_ids`, `false_positive_notes`, `excluded_domains`, `references` | no | as before |

Fields selected by category:

| Field | injection | exposure |
|---|---|---|
| `attack_vector` (a matrix `attackClasses` id whose techniques include `technique_id`) | required | optional, per the join in `schema/exposure-classes.json` |
| `attack_class` (one of the ten canonical classes, derived from the primary list holding `technique_id`) | required | forbidden |
| `exposure_class` | forbidden | required |

Keys prefixed `x_` are admitted for implementer extensions; every other unknown key is rejected.

An injection signature:

```yaml
schema_version: "0.2"
id: AIIS-ATTR-IGNORE-INST-01
category: injection
name: Ignore-previous-instructions injection in HTML attributes
version: 0.1.1
severity: high
technique_id: T-2001
related_technique_ids: []
attack_vector: SOUL-INJECT
attack_class: injection
surface_types: [alt_aria, data_attr, html_comment, meta_tag]
match:
  type: regex
  pattern: '(?i)(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions|disregard\s+(previous|prior|the\s+above)|forget\s+everything\s+(above|before|you))'
cwe_ids: [CWE-74]
hma_check_ids: []
provenance:
  evidence_tier: observed
  first_seen: "2026-04-15"
status: active
```

An exposure signature:

```yaml
schema_version: "0.2"
id: AIIS-EXPOSURE-OLLAMA-TAGS-01
category: exposure
name: Exposed Ollama model listing
version: 0.1.1
severity: medium
technique_id: T-1001
related_technique_ids: []
attack_vector: LLM-EXPOSE
exposure_class: EXPOSURE-SELFHOSTED-LLM
surface_types: [http_body]
match:
  type: composite
  all_of:
    - { type: substring, contains: ["\"models\":"] }
    - { type: substring, contains: ["\"digest\":\"sha256:"] }
    - { type: substring, contains: ["\"parameter_size\":"] }
hma_check_ids: [LLM-001]
provenance:
  evidence_tier: adapted
  source: https://github.com/ollama/ollama/blob/main/docs/api.md
status: draft
```

### Families

The second segment of an id is the family token. `schema/families.json` registers every token. The six tokens of schema 0.1 (`HIDDEN`, `COMMENT`, `META`, `SCRIPT`, `HEADER`, `ATTR`) named a document surface; they are frozen and admit only the ids listed there. `UNICODE` and `EXPOSURE` are open. New injection families are named for the payload, not the surface; `OVERRIDE`, `ROLE`, `JAILBREAK` and `EXFIL` are the reserved next tokens, minted with their first signature. See CONTRIBUTING.md.

## Repository layout

```
signatures/                  # one directory per family token, lowercased
  attr/  comment/  exposure/  header/  hidden/  meta/  script/  unicode/
    <id>.yaml                # file name equals the id
schema/
  aiis-v0.2.schema.json      # the current schema
  aiis-v0.1.schema.json      # kept for readers of corpus v0.1.0 to v0.3.0
  families.json              # family token registry
  exposure-classes.json      # exposure classes and their attack_vector join
retired-ids.yaml             # every retired id with its disposition; ids are never reused
crosswalks/
  technique-signatures.json  # generated: techniques to signatures and back
vendor/
  agent-threat-matrix/       # matrix.json and canonical-classes.json at a recorded commit
  hackmyagent/               # check id list generated from the published package
tests/
  fixtures/<id>.json         # shouldMatch and shouldNotMatch cases per signature
  validate/                  # the validator (Go, vendored dependencies, runs offline)
```

## Validating

```
cd tests/validate
go test -mod=vendor ./...
go run -mod=vendor .
```

The validator runs thirteen checks and exits non zero on any failure: schema validation, the id grammar, the family registry and layout, technique resolution, the canonical class, the attack vector, the exposure class, vocabulary disjointness, fixture presence, every fixture case through the matcher, the retired id list, the crosswalk, and the vendor manifests. A missing `provenance.source` or `provenance.first_seen` on an active signature prints a warning. `go run -mod=vendor . -write-crosswalk` regenerates `crosswalks/technique-signatures.json`.

## Using AIIS signatures

- **OpenA2A HoneyMap** consumes these signatures as its first classifier tier.
- **HackMyAgent**: each signature may name, in `hma_check_ids`, the HackMyAgent check from HackMyAgent's own taxonomy that detects the same payload family on local agent files; the field is empty where none exists.
- **DVAA** uses AIIS-derived attack scenarios for lab reproduction.
- **Any third-party scanner** can implement the schema and reuse the signature pack.

## Contributing

This standard is early and authored in the open. We are looking for co-authors, an independent second implementation, and high-precision signature contributions before it goes to an external standards body. See [CONTRIBUTING.md](CONTRIBUTING.md) for the review process, for minting a family and for retiring a signature. The corpus is intentionally conservative: high-precision, low-false-positive patterns over coverage.

## License

Apache License 2.0. See `LICENSE`.

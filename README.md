# AIIS Signatures

**AI Injection and Infrastructure Signature Standard** — an open, YARA-style detection format for AI agent prompt injections and public AI-agent infrastructure exposure.

AIIS is the public counterpart of the OpenA2A HoneyMap scanner and is published here under Apache License 2.0. Anyone can read, reuse, extend, or contribute signatures. The goal is an interoperable detection standard, the way YARA became one for malware.

## Start here

Open [`signatures/`](signatures/) first: one YAML file per signature, in a directory named for its family token. An excerpt of [`signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml`](signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml):

```yaml
# ...
id: AIIS-ATTR-IGNORE-INST-01
category: injection
name: Ignore-previous-instructions injection in HTML attributes
# ...
severity: high
technique_id: T-2001
related_technique_ids: []
attack_vector: SOUL-INJECT
attack_class: injection
surface_types: [alt_aria, data_attr, html_comment, meta_tag]
match:
  type: regex
  pattern: '(?i)(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions|disregard\s+(previous|prior|the\s+above)|forget\s+everything\s+(above|before|you))'
# ...
status: active
```

Every field is described in [`docs/schema.md`](docs/schema.md).

## Use cases

### A web page tells your agent what to do, and every scanner spells the rule differently

A page carries an instruction in hidden text, an HTML comment, a meta tag or a tool description. Each scanner that looks for this writes its own private rules, so nothing can be shared or compared, and a site owner has no common rule set to test their own pages against.

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

Where it stops today: the RAG service, AI copilot and tool registry exposure classes are reserved as valid values with no signature yet.

Why you can check this yourself: the schema is under [`schema/`](schema/) and described in [`docs/schema.md`](docs/schema.md); the signatures are under [`signatures/`](signatures/) with one fixture file per signature in [`tests/fixtures/`](tests/fixtures/); the validator in [`tests/validate/`](tests/validate/) runs [its checks](docs/validating.md) with vendored dependencies and no network; [`CHANGELOG.md`](CHANGELOG.md) records the current corpus release; and the matrix the signatures cite is pinned under [`vendor/agent-threat-matrix/`](vendor/agent-threat-matrix/).

## Scope

A signature is evaluated against one document: a page, a header set, a response body, a tool description, a governance file. Behaviour that can only be judged across a session or from telemetry (what an agent did, in which order, with which tool results) is out of scope for this format; behavioural formats are a sibling specification.

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

Where it stops today: no shipped signature yet declares `json_ld`, `open_graph`, `noscript`, `inline_style`, `tool_description`, `tool_result`, `tool_error`, `governance_file`, `memory_entry` or `skill_frontmatter` in its `surface_types`; the schema accepts each of these values.

### Exposure category

Fingerprints of publicly reachable AI infrastructure, one `exposure_class` each (`schema/exposure-classes.json`):

- `EXPOSURE-MCP-SERVER`: MCP server JSON-RPC response shapes
- `EXPOSURE-LLM-GATEWAY`: LLM gateways such as LiteLLM
- `EXPOSURE-SELFHOSTED-LLM`: Ollama, vLLM, llama.cpp, LocalAI
- `EXPOSURE-AGENT-FRAMEWORK`: LangServe, AutoGen, CrewAI
- `EXPOSURE-VECTOR-DB`: Chroma, Qdrant, Milvus, Weaviate
- `EXPOSURE-RAG-SERVICE`, `EXPOSURE-AI-COPILOT`, `EXPOSURE-TOOL-REGISTRY`: reserved, valid values with no signature yet

## Validating

```
cd tests/validate
go test -mod=vendor ./...
go run -mod=vendor .
```

The validator exits 1 when any check fails. A missing `provenance.source` or `provenance.first_seen` on an active signature prints a warning. `go run -mod=vendor . -write-crosswalk` regenerates `crosswalks/technique-signatures.json`. Every check it runs is listed in [`docs/validating.md`](docs/validating.md).

## Using AIIS signatures

- **OpenA2A HoneyMap** consumes these signatures as its first classifier tier.
- **HackMyAgent**: each signature may name, in `hma_check_ids`, the HackMyAgent check from HackMyAgent's own taxonomy that detects the same payload family on local agent files; the field is empty where none exists.
- **DVAA** uses AIIS-derived attack scenarios for lab reproduction.
- **Any third-party scanner** can implement the schema and reuse the signature pack.

## Documentation

- [`docs/schema.md`](docs/schema.md): the two signature categories, every field, one example signature per category, and the family tokens.
- [`docs/validating.md`](docs/validating.md): each check the validator runs, its warnings, and regenerating the crosswalk.
- [`docs/use-cases.md`](docs/use-cases.md): the longer problem statement behind the first use case.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): the review process, the repository layout, minting a family and retiring a signature.
- [`CHANGELOG.md`](CHANGELOG.md): each corpus and schema release.

## License

Apache License 2.0. See `LICENSE`.

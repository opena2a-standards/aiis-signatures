# AIIS signature schema

The format of an AIIS signature file: its two categories, the surfaces an injection hides in, its fields, two example signatures and the family tokens. The JSON Schema files are under [`schema/`](../schema/).

## Two signature categories

Every signature declares a `category`, and the category selects which classification fields it must carry:

- **`injection`** matches a prompt injection artefact embedded in a document: hidden text, HTML comments, script literals, meta tags, attributes, headers, tool descriptions. It detects the attack payload and carries a matrix `attack_vector` and a canonical `attack_class`.
- **`exposure`** matches evidence that a host publicly exposes an AI component: an MCP server, an LLM gateway, a self-hosted inference server, an agent framework, a vector database. It detects the attack surface, not a specific attack, and carries an `exposure_class`.

There is no default category in schema 0.2.

### Injection surfaces

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

## Schema

Each signature is a YAML file at `signatures/<family>/<id>.yaml` conforming to `schema/aiis-v0.2.schema.json` (JSON Schema draft 2020-12). Schema 0.1 stays in the repository for readers of the earlier releases and is not used by the validator.

Fields common to both categories:

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | the constant `"0.2"` |
| `id` | yes | `AIIS-<FAMILY>-<NAME>-<NN>`; the family token is registered in `schema/families.json` and the file lives in `signatures/<family lowercased>/` |
| `name`, `version`, `severity`, `status` | yes | as before; `status` is `draft` or `active`, and a retired signature is deleted and recorded in `retired-ids.yaml` |
| `description` | no | free text: what the signature detects |
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

# AIIS Signatures changelog

## v0.2.1 — 2026-05-11

False-positive reduction in the two highest-volume seed signatures, which
together produced ~72% of HoneyMap dashboard surfaces and were dominated by
matches on legitimate government / education / news / docs content.

**Schema changes (`aiis-v0.1.schema.json`):**

- New optional `excluded_domains` field (list of host-regex patterns,
  anchored `^...$` and case-insensitive at the engine level). When a
  surface's source domain matches any entry, the signature is skipped for
  that surface. Backward-compatible — existing signatures omit the field
  and behave identically.

**Signature updates (both bumped to `version: 0.2.0` internally):**

- `AIIS-ATTR-EXFIL-URL-01` — replaced the broad
  `(verb) (this|the|all|your|user|conversation|history|context) … URL` regex
  with one that requires the verb, an unambiguous AI/agent-context object
  (`conversation`, `chat`, `context`, `system prompt`, `api key`, `secret`,
  `token`, `credential`, `tool call/output`, `user input/prompt/message`,
  qualified forms like `conversation history`, …), and the URL to co-occur
  within ~80 characters. Excludes human-targeted CTAs such as
  "submit your application at https://…", "send all your inquiries to https://…".
- `AIIS-HIDDEN-ROLE-INJECT-01` — added `excluded_domains` covering
  security-research, standards, and major-vendor docs hosts (NIST, CISA,
  MITRE, OWASP, arXiv, Anthropic, OpenAI, Wikipedia, GitHub Pages, …) that
  routinely quote injection samples verbatim as educational content. The
  signature's `false_positive_notes` had called for this allowlist since
  v0.1.0; the standard now expresses it.

## v0.2.0 — 2026-04-21

Introduces the `exposure` signature category alongside `injection`. Schema is
backward-compatible: signatures without an explicit `category` default to
`injection`.

**Schema changes (`aiis-v0.1.schema.json`):**

- New `category` field, enum `["injection", "exposure"]`, default `"injection"`.
- `surface_types` enum extended with `http_body` and `tls_cert` to support
  fingerprint matching against live service responses.

**New seed signatures (8, all `status: draft` pending review):**

- `AIIS-EXPOSURE-OLLAMA-TAGS-01` — Ollama `/api/tags` listing
- `AIIS-EXPOSURE-OLLAMA-VERSION-01` — Ollama `/api/version` response
- `AIIS-EXPOSURE-VLLM-MODELS-01` — vLLM OpenAI-compatible `/v1/models` with `owned_by:"vllm"`
- `AIIS-EXPOSURE-LITELLM-MODELS-01` — LiteLLM proxy `litellm_params` / `healthy_endpoints`
- `AIIS-EXPOSURE-MCP-JSONRPC-01` — MCP server `tools/list` / `resources/list` response
- `AIIS-EXPOSURE-LANGSERVE-ROUTES-01` — LangServe runnable OpenAPI spec
- `AIIS-EXPOSURE-CHROMA-HEARTBEAT-01` — Chroma `/api/v1/heartbeat`
- `AIIS-EXPOSURE-QDRANT-ROOT-01` — Qdrant `/` root response

**Pending follow-on seeds (exposure subclasses not covered in v0.2.0):**

- `EXPOSURE-RAG-SERVICE` — Haystack, RAGFlow
- `EXPOSURE-AI-COPILOT` — self-hosted Copilot-style proxies
- `EXPOSURE-TOOL-REGISTRY` — MCP catalogues, tool registries
- `EXPOSURE-AUTH-MISCONFIG` — unauthenticated admin/management endpoints
- `EXPOSURE-VERSION-DRIFT` — per-CVE matchers, populated from vulnerability data

## v0.1.0 — 2026-04-14

Initial public release. 10 seed signatures across 6 surface types:

- `AIIS-HIDDEN-ROLE-INJECT-01` — role marker + override in hidden text
- `AIIS-HIDDEN-CHATML-01` — ChatML role tags in hidden text
- `AIIS-HIDDEN-JAILBREAK-DAN-01` — DAN-family jailbreak in hidden text
- `AIIS-ATTR-IGNORE-INST-01` — "ignore previous instructions" in HTML attrs
- `AIIS-ATTR-EXFIL-URL-01` — exfil instruction + URL in HTML attrs
- `AIIS-SCRIPT-ROLE-PLAY-01` — role-play jailbreak in script literal
- `AIIS-META-LLM-OVERRIDE-01` — unauthorized llms.txt / meta directive
- `AIIS-UNICODE-TAG-BLOCK-01` — Unicode Tag block steganography
- `AIIS-COMMENT-SYSTEM-OVERRIDE-01` — system override in HTML comment
- `AIIS-HEADER-INJECT-01` — prompt injection in custom HTTP header

Schema `aiis-v0.1.schema.json`. All signatures Apache 2.0.

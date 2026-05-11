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
  with a `composite any_of` (bidirectional: URL may precede or follow the
  verb-object phrase within 150 characters) that requires the verb, an
  unambiguous AI/agent-context-or-security-critical object, and the URL.
  - Verbs: `send / post / submit / upload / transmit / forward / exfiltrate
    / leak / deliver / relay / copy / share / dump / exfil / siphon`.
    `extract / export / return / emit / beacon / ship` were considered then
    dropped — they introduced new FPs on password-manager onboarding
    ("Extract the password from your vault at …"), GDPR cookie-banner copy
    ("Export your cookie preferences at …"), and aria-label navigation
    ("Return to https://help.example.com/orders").
  - Objects: `conversation / chat / context / (system) prompt / api key /
    secret / token / bearer / jwt / oauth code / kerberos ticket / saml
    assertion / auth header / X-API-Key header / password / passphrase /
    credential / cookie / session token / (private|ssh|gpg|signing|
    encryption|access) key / recovery code / mnemonic / seed phrase /
    env variable / memory state / knowledge base / tool call/response/
    output / user input/prompt/query/message/data`, plus qualified forms
    `conversation history`, `chat transcript`, `system message`, etc.
  - Bare ambiguous nouns (`history`, `messages`, `transcript`, `dialogue`,
    `files`, `documents`) are NOT in the unqualified object set — they
    only match when explicitly qualified (`conversation history`, `user
    messages`). This excludes human-targeted CTAs like "submit your
    application at https://…", "send all your inquiries to https://…",
    "upload your transcript to https://admissions.example.edu/...".

- `AIIS-HIDDEN-ROLE-INJECT-01` — added `excluded_domains` covering
  authoritative security-research, standards, and major-vendor docs
  publishers (NIST, CISA, NSA, MITRE, OWASP, arXiv, IEEE, ACM, USENIX,
  `www.w3.org`, `www.ietf.org`, `docs.anthropic.com`, `platform.openai.com`,
  `learn.microsoft.com`, `ai.google.dev`, etc.) that routinely quote
  injection samples verbatim as educational content. The signature's
  `false_positive_notes` had called for this allowlist since v0.1.0; the
  standard now expresses it.
  - Multi-tenant user-content hosts are deliberately NOT exempted
    (`github.io`, `githubusercontent.com`, `readthedocs.io`, `medium.com`,
    `substack.com`, `stack{exchange,overflow}.com`) — anyone can register
    a subdomain, so blanket exemption is an attacker-controlled bypass
    channel. Add specific known-publisher subdomains case by case
    (`owasp.github.io`, `mitre.github.io`, `mitre-attack.github.io`).
  - User-edited platforms (`wikipedia.org`, `wikimedia.org`,
    `developer.mozilla.org`) are NOT exempted either — the edit-then-
    revert window is long enough for a crawler ingest cycle to pick up
    an injection sample.
  - Mailing-list-archive subdomains on standards-body hosts
    (`lists.w3.org`, `mailarchive.ietf.org`, `datatracker.ietf.org`) are
    NOT exempted — only the canonical-spec roots are.

**Known coverage gaps deferred to the NLM-INJ tier of HoneyMap's cascade:**

The AIIS regex tier is intentionally English-only and lookalike-blind.
v0.2.1 is no worse than v0.1.0 on any of these (the gap is the tier, not
the version bump):

- Non-English exfil verbs ("envíalo a", "送信して", "送往", …).
- Zero-width joiner / non-joiner insertion inside verbs or objects
  ("se‍nd the api key").
- Cyrillic / Greek homoglyph substitution ("ѕend the api key").
- HTML tag injection between verb and object inside an attribute value
  ("send the&lt;br/&gt;api key to https://...").

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

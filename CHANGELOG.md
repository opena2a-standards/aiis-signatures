# AIIS Signatures changelog

## v0.3.0 — 2026-07-07

Precision fixes in the two highest-volume hidden-text signatures (DAN and
role-injection), plus the regional-flag-emoji exclusion for the Unicode Tag-block
signature. Adds a `tests/fixtures/` corpus (representative false-positive and
real cases per signature) exercised by the HoneyMap reference implementation.

**Schema changes (`aiis-v0.1.schema.json`):**

- New optional `exclude_emoji_tag_flags` boolean on `unicode_range` matches. When
  true, well-formed regional-indicator flag emoji (U+1F3F4 base + Tag characters
  + U+E007F terminator) are stripped before counting Tag-block characters.
  Backward-compatible — omitted defaults to `false`.

**Signature updates:**

- `AIIS-HIDDEN-JAILBREAK-DAN-01` (`0.1.0` → `0.2.0`) — requires unambiguous
  AI-injection framing. The v0.1.0 pattern alternated on bare `developer mode`,
  bare `jailbreak`, and bare `DAN mode`, which matched benign content unrelated
  to prompt injection: OS "developer mode" UI strings and WordPress plugin debug
  output ("Developer mode initialization; Version: 1.2.9"), iPhone "jailbreak"
  tutorials, and cross-language substrings where `dan mode` appears inside a word
  ("dan modern" — Indonesian "and modern"; "nedan modereras" — Swedish "below is
  moderated"). The bare branches are dropped; every surviving branch requires
  explicit framing. The `jailbreak` branch takes an explicit AI/agent object
  (`ai|assistant|agent|system prompt|model|bot|llm|chatbot|prompt|gpt|chatgpt|
  claude|gemini|guardrails|filters|rules|restrictions|safety`) — the object is
  `system prompt`, not bare `system`, so "jailbreak the agent / the system
  prompt / ChatGPT / your guardrails" match but "jailbreak your iPhone" and
  device articles ("to jailbreak the system you first unlock the bootloader") do
  not; the `DAN mode` branch is gated on a leading cue ("you are (now) in DAN
  mode", enter/activate/stay in/remain in DAN mode) so gaming and martial-arts
  uses ("Dan mode is unlocked in Street Fighter", "3rd dan mode" in a karate
  bracket) and "Sudan"/"nedan modereras" do not match; and the
  ignore/disregard/forget-instructions family covers previous/prior/above/
  following/earlier targets. Recall is deliberately bounded to explicit framing —
  a single-token, delimiter-free jailbreak mention is a known, documented recall
  limitation of the census, not a silently-backstopped gap (the reference
  scanner has no post-hoc tier that recovers a surface the pattern did not
  match).

- `AIIS-HIDDEN-ROLE-INJECT-01` (`0.2.0` → `0.3.0`) — requires an injection
  DELIMITER around the role word. The v0.2.0 pattern made the brackets optional
  (`\[? … \]?`), so a bare role word anywhere in prose matched — most
  destructively `INST` inside "instructions" ("further instructions. Don't forget
  to override the defaults") — and quote-wrapped roles in serialized data (Redux
  `window.__INITIAL_STATE__` dumps, consent JSON: `"system"`, `["system","user"]`)
  matched too. Rather than requiring square brackets specifically (which would
  also drop the common non-`[…]` markers `System:`, `<system>`, `{{system}}`,
  `Admin:` — all real injection forms), a match now requires one of two shapes:
  (a) the role word wrapped in a MATCHED injection delimiter — both opening and
  closing present and adjacent: a bracket (`[system]`), an angle/ChatML tag
  (`<system>`, `</system>`, `<|system|>`), or a brace (`{system}`, `{{system}}`)
  — then an override verb within 200 chars; or (b) a start- or
  whitespace-anchored `role:` directive with the override verb within a tight
  12-char window. The delimiter set excludes the double-quote (so JSON/Redux
  roles stay out) and the directive anchor is start-or-whitespace (so
  `subsystem:`/`filesystem:`/`ecosystem:` stay out). Requiring a MATCHED (not
  lone or optional) delimiter — no bare `{`, `#`, or markdown-heading shape —
  additionally keeps out benign markdown headings (`## Instructions … override`),
  JS/JSON object literals (`{ user: 'bob' } … override`), and role words that are
  only substrings (`user` in "Username"). The role vocabulary is the full
  ChatML/OpenAI set and the verb set adds `bypass`, `you must`, `do not tell`.
  `excluded_domains` is unchanged.

- `AIIS-UNICODE-TAG-BLOCK-01` (`0.1.0` → `0.2.0`) — enables
  `exclude_emoji_tag_flags`. Regional flag emoji (England, Scotland, Wales) are
  legitimately encoded with Tag characters and were matched as steganographic
  injection. The reference matcher strips ONLY the three RGI-valid flag bodies
  (`gbeng`/`gbsct`/`gbwls`); any other base…Tag…terminator sequence — including an
  attacker hiding a tag-encoded payload behind a flag wrapper, or splitting one
  across several short wrappers — is retained and counted. A real payload carrying
  bare Tag characters (with or without a flag alongside) still matches, and a
  malformed flag (base with Tag characters but no terminator) is still counted.

**Test fixtures (`tests/fixtures/<SIGNATURE-ID>.json`):**

- New per-signature `shouldMatch` / `shouldNotMatch` corpora for the three
  updated signatures. Text cases carry the string directly; Unicode cases carry
  hex `codepoints` to avoid embedding invisible Tag characters in the repo. The
  HoneyMap reference implementation loads these and asserts each signature's
  matcher agrees with the fixture, so the format has an executable conformance
  check even though this repo ships no runner of its own.

**Tooling / CI:**

- Adds `.github/workflows/validate.yml` and a self-contained, stdlib-only
  validator (`tests/validate/`). On every push and pull request it compiles
  every signature `pattern` with Go RE2 (the same engine HoneyMap uses) and runs
  the plain-text fixtures against the compiled pattern, so a malformed pattern or
  a detection regression is caught in this repo — previously there was no CI at
  all. Codepoint-based (Unicode Tag) fixtures are exercised by HoneyMap's own
  test suite, which now checks this repo out as a sibling so those tests run
  instead of skipping.

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

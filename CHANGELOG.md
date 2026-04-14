# AIIS Signatures changelog

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

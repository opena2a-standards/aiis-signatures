# Contributing to AIIS

The AI Injection and Infrastructure Signature Standard is authored in the open and published with a working reference implementation (the OpenA2A HoneyMap scanner). It is early, and we are looking for co-authors and contributors to help shape it before it goes to an external standards body. Your review, critique, and independent implementation work all carry weight on the spec.

## What we are looking for

- Review and critique. Read the [schema](schema/) and the existing [signatures](signatures/) and tell us where the format is ambiguous, where it leaves interoperability gaps, or where a signature is over-broad or imprecise.
- An independent second implementation. A non-HoneyMap engine that loads and matches AIIS signatures is the strongest signal that the format is sound and portable.
- Security audit and threat modeling of the spec itself, not just an implementation.
- Cryptography and signatures expertise, applied to detection-signature design. We want input from people who have built YARA rules, detection corpora, or injection and exposure fingerprints, and who can contribute high-precision, low-false-positive patterns. The corpus is intentionally conservative, so precision matters more than coverage.
- We need high-precision attack signatures and review from applied-cryptography researchers.

## Who we are looking for

We especially welcome:

- Security and cryptography researchers, including academic and PhD-level work.
- Standards-process experts (W3C, IETF, OpenTelemetry) who can help take these specifications to external bodies.
- Engineers building agent platforms and runtimes, for independent implementations and adoption.
- Red teamers and security auditors.

## How to contribute

- Open an issue or pull request on this repository.
- Or email info@opena2a.org with "co-author" in the subject line.
- For new attack signatures, injection research, or coordinated disclosure, email info@opena2a.org or info@opena2a.org.

Small fixes (typos, broken links, clarifications) can go straight to a pull request. For new signatures or changes to the signature schema, open an issue first so the change can be discussed and validated against the test corpus before implementation work begins.

## Minting a family

The family token is the second segment of a signature id (`AIIS-<FAMILY>-<NAME>-<NN>`) and every token is registered in `schema/families.json`. A new token is minted by one pull request that carries, together:

- the `families.json` entry (token, category, status `open`, description, `mintedIn` set to the release that will ship it);
- at least one signature using the token, with its `tests/fixtures/<id>.json`;
- a CHANGELOG line naming the token;
- one paragraph explaining why no existing family fits.

Injection families are named for the payload, not for the document surface. `OVERRIDE`, `ROLE`, `JAILBREAK` and `EXFIL` are the reserved next tokens; they are minted with their first signature, not ahead of it. The six surface tokens of schema 0.1 (`HIDDEN`, `COMMENT`, `META`, `SCRIPT`, `HEADER`, `ATTR`) are frozen: they admit no new ids, and the validator rejects an id under a frozen token that is not in that token's allowlist. The maintainers approve a new token; a pull request missing any of the four parts is not merged.

## Retiring a signature

A signature is retired by deleting its file and adding a record to `retired-ids.yaml` in the same pull request, with the id, the disposition (`retired`, or `superseded` or `superseded_narrowed` with `superseded_by` naming the live signature that carries the intent), `retired_at`, `retired_in` and a reason. The validator compares `signatures/` with the merge base and fails when a signature disappears without a record. Ids are never reused: a retired id stays in `retired-ids.yaml` for good, and a replacement takes the next sequence number.

## Ground rules

- Contributions are licensed under Apache-2.0, consistent with the project license.
- Be specific and evidence-based. A new signature should cite the artefact or exposure it matches and include a test case.
- No purely theoretical claims without a path to validation. Prefer high-precision patterns proven against real samples over broad patterns that raise false positives.

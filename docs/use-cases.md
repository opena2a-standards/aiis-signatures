# Use cases

Each use case below says what you can check today and where it stops.

## Who reads this

| Reader | The question they bring | Where it is answered |
|---|---|---|
| Security leader or CISO | How do I compare one vendor's injection detection with another's, and what evidence do I ask for? | The use case [A vendor says its tool detects prompt injection](#a-vendor-says-its-tool-detects-prompt-injection) |
| IAM professional or identity architect | Does this touch identity or access at all? | Only at the edge. AIIS authenticates nothing and grants nothing. Its exposure signatures match evidence that a host publicly exposes an AI component ([`docs/schema.md:10`](schema.md#two-signature-categories)), and the MCP server signature carries CWE-284, improper access control ([`AIIS-EXPOSURE-MCP-JSONRPC-01.yaml:25`](../signatures/exposure/AIIS-EXPOSURE-MCP-JSONRPC-01.yaml)); see [Your MCP server is on the public internet and you did not know](#your-mcp-server-is-on-the-public-internet-and-you-did-not-know) |
| Platform or security engineer | Which of our AI services can be reached from the internet, and how is each one recognised? | The use case [Your MCP server is on the public internet and you did not know](#your-mcp-server-is-on-the-public-internet-and-you-did-not-know) and the class list in [`schema/exposure-classes.json`](../schema/exposure-classes.json) |
| Agent developer or implementer | What must my matcher implement, and how do I know it agrees with the reference? | [`docs/schema.md`](schema.md) and the use case [A second scanner must flag the same pages](#a-second-scanner-must-flag-the-same-pages) |
| GRC, audit or compliance reader | What does one detection rule map to, how established is the attack behind it, and which record do I read? | The use case [An auditor asks what one detection rule rests on](#an-auditor-asks-what-one-detection-rule-rests-on) |
| Standards reviewer (IETF or AIW participant) | What problem does this solve, how does it relate to existing formats, and how mature is it? | The use case [A standards reviewer asks whether the format is ready](#a-standards-reviewer-asks-whether-the-format-is-ready), [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`CHANGELOG.md`](../CHANGELOG.md) |

## A web page tells your agent what to do, and every scanner spells the rule differently

A page carries an instruction in hidden text, an HTML comment, a meta tag or a tool description. The agent reading it cannot tell that text from its task. Each scanner that looks for this writes its own private rules, so nothing can be shared or compared, and a site owner has no common rule set to test their own pages against.

AIIS is a YAML signature format, in the spirit of YARA, evaluated against one document. An injection signature detects the payload and carries the Agent Threat Matrix attack vector and canonical attack class, and every signature ships with fixture cases that must match and must not match.

What you can do today: run the validator, which checks every signature and every fixture case offline.

```
git clone https://github.com/opena2a-standards/aiis-signatures
cd aiis-signatures/tests/validate
go run -mod=vendor .
```

Where it stops today: a signature judges one document. Behaviour that can be judged across a session, such as what an agent did in which order, is out of scope for this format. No signature yet targets tool descriptions: the schema accepts `tool_description` as a surface type, but no shipped signature declares it.

## Your MCP server is on the public internet and you did not know

Teams stand up MCP servers, LLM gateways, self-hosted inference servers and vector databases, and some end up reachable from the internet.

Exposure signatures fingerprint publicly reachable AI infrastructure and carry an exposure class, so a scanner can tell an operator what is exposed, not just that something answered.

What you can do today: read the signatures under `signatures/exposure/` and the class list in `schema/exposure-classes.json`, and run the validator above.

Where it stops today: the RAG service, AI copilot and tool registry exposure classes are reserved as valid values with no signature yet.

## A vendor says its tool detects prompt injection

Two vendors both say their tools catch instructions hidden in web pages. The security leader cannot compare the claims: each vendor's rules are private, and neither says what its rules would miss or what they would flag by mistake.

Reader: security leader or CISO.

Without AIIS: a detection claim is a statement about private rules, with nothing to test it against.

What AIIS does: a signature is an open file with a stable id, a version, a severity, a status and a match rule ([`docs/schema.md:39-52`](schema.md#schema)). An injection signature names the Agent Threat Matrix technique it detects and carries the matrix attack vector and canonical attack class ([`docs/schema.md:46`](schema.md#schema), [`docs/schema.md:56-60`](schema.md#schema)). Every signature ships with fixture cases that must match and cases that must not, and the validator runs every case through its matcher ([`docs/validating.md:11`](validating.md)). The risk this addresses is buying a detection whose coverage and false positives nobody outside the vendor can check. A requirement can name signature ids and their fixture files: the vendor states which ids its tool evaluates and reports its result on each fixture case.

What you can do today: run the validator and read its schema, fixture and matcher checks.

```bash
(cd tests/validate && go run -mod=vendor .) | grep -E "check +(1|9|10) |checks reported"
```

```
ok   check  1 schema 0.2 (18 signatures)
ok   check  9 fixtures present with at least three cases each way
ok   check 10 fixture cases agree with the matcher
13 of 13 checks reported, 0 failure(s), 13 warning(s)
```

Where it stops today: the fixtures run through the reference matcher in [`tests/validate/`](../tests/validate/); there is no packaged runner that takes another tool's results.

Out of scope: behaviour that can only be judged across a session or from telemetry ([`README.md:36`](../README.md#scope)).

## An auditor asks what one detection rule rests on

A detection fired on a page an agent read, and the incident report cites the rule. The auditor asks what the rule detects, which known attack it relates to, how established that attack is, and whether the rule has changed since.

Reader: GRC, audit or compliance reader.

Without AIIS: a detection is named by a vendor's internal rule, with no stable link to a public catalog.

What AIIS does: each signature names its primary threat matrix technique, resolved against the vendored `matrix.json` ([`docs/schema.md:46`](schema.md#schema)), and may list CWE ids ([`docs/schema.md:52`](schema.md#schema)). It carries a version and a status, and a retired signature is deleted and recorded in `retired-ids.yaml` ([`docs/schema.md:43`](schema.md#schema)), whose ids are never reused ([`CONTRIBUTING.md:43`](../CONTRIBUTING.md#retiring-a-signature)). An active signature carries provenance with an evidence tier: observed, validated or adapted ([`docs/schema.md:50`](schema.md#schema)). The mappings the repository makes are to threat matrix techniques and CWE ids; the OASB controls listed for a technique come from the vendored matrix, at the release recorded in [`vendor/agent-threat-matrix/VENDOR.json`](../vendor/agent-threat-matrix/VENDOR.json), not from AIIS. The records an auditor reads are the signature file at its version, its fixture file, and its entry in [`crosswalks/technique-signatures.json`](../crosswalks/technique-signatures.json).

What you can do today: read one signature's mapping fields, its crosswalk entry, and what the validator says about it.

```bash
grep -E "^(id|version|severity|technique_id|cwe_ids|status):|^provenance:|^  (evidence_tier|source|first_seen):" signatures/attr/AIIS-ATTR-IGNORE-INST-01.yaml
jq -c '.bySignature["AIIS-ATTR-IGNORE-INST-01"]' crosswalks/technique-signatures.json
(cd tests/validate && go run -mod=vendor .) | grep "IGNORE-INST"
```

```
id: AIIS-ATTR-IGNORE-INST-01
version: 0.1.1
severity: high
technique_id: T-2001
cwe_ids: [CWE-74]
provenance:
  evidence_tier: observed
  first_seen: "2026-04-15"
status: active
{"techniqueId":"T-2001","relatedTechniqueIds":[]}
WARNING AIIS-ATTR-IGNORE-INST-01 is active without provenance.source
```

Where it stops today: `provenance.source` and `provenance.first_seen` are optional, so an active signature can carry an evidence tier with no cited source; the validator prints a warning for each such gap, as it does here.

Out of scope: a match is evidence that the payload is in the document, not that an agent read it or acted on it ([`README.md:34-36`](../README.md#scope)).

## A second scanner must flag the same pages

A team adds AIIS support to its own scanner. The same page is checked by their scanner and by another one. If the two implement a match rule differently, one flags the page and the other does not, and nobody can say which is right.

Reader: agent developer or implementer.

Without AIIS: two implementations of the same rule drift apart unnoticed.

What AIIS does: the match types are fixed: `regex`, `substring`, `unicode_range`, and `composite` with `all_of` and `any_of`, recursively ([`docs/schema.md:49`](schema.md#schema)). Unknown keys are rejected, and keys prefixed `x_` are admitted for implementer extensions ([`docs/schema.md:62`](schema.md#schema)). Each signature's fixture file lists cases that must match and cases that must not, at least three each way, and the reference matcher must agree with every case ([`docs/validating.md:11`](validating.md)). The first things to implement are the four match types; then run every fixture case through your matcher and compare the result with its list.

What you can do today: count one fixture file's cases, then run the two fixture checks.

```bash
jq -c '{signature, surface, shouldMatch: (.shouldMatch | length), shouldNotMatch: (.shouldNotMatch | length)}' tests/fixtures/AIIS-ATTR-IGNORE-INST-01.json
(cd tests/validate && go run -mod=vendor .) | grep -E "check +(9|10) "
```

```
{"signature":"AIIS-ATTR-IGNORE-INST-01","surface":"alt_aria","shouldMatch":5,"shouldNotMatch":5}
ok   check  9 fixtures present with at least three cases each way
ok   check 10 fixture cases agree with the matcher
```

Where it stops today: the schema and its documentation do not name a regular expression dialect, so a pattern that one engine accepts may behave differently in another; the reference matcher is the Go program in [`tests/validate/`](../tests/validate/).

Out of scope: a signature is evaluated against one document ([`README.md:34`](../README.md#scope)); how a scanner obtains that document is its own.

## A standards reviewer asks whether the format is ready

A participant at a standards meeting is asked to look at AIIS. They want to know what problem it solves, how it relates to formats that exist, how mature it is, and how changes are decided.

Reader: standards reviewer (IETF or AIW participant).

What the repository says about itself: the problem is that every scanner looking for injected instructions writes its own private rules, so nothing can be shared or compared (the first use case above). It describes itself as a YARA-style detection format whose goal is an interoperable detection standard, the way YARA became one for malware ([`README.md:3-5`](../README.md)). A signature judges one document; behaviour across a session belongs to a sibling specification ([`README.md:34-36`](../README.md#scope)). The schema is version 0.2 ([`docs/schema.md:41`](schema.md#schema)). The standard describes itself as early, and asks for co-authors, an independent second implementation and high-precision signatures before it goes to an external standards body ([`CONTRIBUTING.md:3`](../CONTRIBUTING.md), [`CONTRIBUTING.md:75`](../CONTRIBUTING.md#contributing)). Retiring a signature takes a recorded disposition, and ids are never reused ([`CONTRIBUTING.md:43`](../CONTRIBUTING.md#retiring-a-signature)).

What you can do today: count the signatures by status, and read the validator's summary.

```bash
grep -h "^status:" signatures/*/*.yaml | sort | uniq -c
(cd tests/validate && go run -mod=vendor .) | tail -1
```

```
  10 status: active
   8 status: draft
13 of 13 checks reported, 0 failure(s), 13 warning(s)
```

Where it stops today: the repository compares the format with YARA only and does not relate it to other detection rule formats. The threat matrix release that technique ids resolve against is pinned in [`vendor/agent-threat-matrix/VENDOR.json`](../vendor/agent-threat-matrix/VENDOR.json) (1.1), behind the matrix's own repository (1.2).

Out of scope: behavioural detection across a session, which the README assigns to a sibling specification.

Why you can check this yourself: the schema is under [`schema/`](../schema/) and described in [`docs/schema.md`](schema.md); the signatures are under [`signatures/`](../signatures/) with one fixture file per signature in [`tests/fixtures/`](../tests/fixtures/); the validator in [`tests/validate/`](../tests/validate/) runs [its checks](validating.md) with vendored dependencies and no network; [`CHANGELOG.md`](../CHANGELOG.md) records the current corpus release; and the matrix the signatures cite is pinned under [`vendor/agent-threat-matrix/`](../vendor/agent-threat-matrix/).

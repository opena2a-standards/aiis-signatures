# Use cases

Each use case below says what you can check today and where it stops.

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

Why you can check this yourself: the schema is under [`schema/`](../schema/) and described in [`docs/schema.md`](schema.md); the signatures are under [`signatures/`](../signatures/) with one fixture file per signature in [`tests/fixtures/`](../tests/fixtures/); the validator in [`tests/validate/`](../tests/validate/) runs [its checks](validating.md) with vendored dependencies and no network; [`CHANGELOG.md`](../CHANGELOG.md) records the current corpus release; and the matrix the signatures cite is pinned under [`vendor/agent-threat-matrix/`](../vendor/agent-threat-matrix/).

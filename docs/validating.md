# Validating

Run from the repository root:

```
cd tests/validate
go test -mod=vendor ./...
go run -mod=vendor .
```

The validator runs fourteen checks and exits non zero on any failure: schema validation, the id grammar, the family registry and layout, technique resolution, the canonical class, the attack vector, the exposure class, vocabulary disjointness, fixture presence, every fixture case through the matcher, the retired id list, the crosswalk, the vendor manifests, and the absence of advisory identifiers and advisory URLs. A missing `provenance.source` or `provenance.first_seen` on an active signature prints a warning. `go run -mod=vendor . -write-crosswalk` regenerates `crosswalks/technique-signatures.json`.

A signature describes a class of content and names no individual advisory: it names its class, its technique ids and its CWE ids (`cwe_ids`) instead. Check 14 holds every file under `signatures/` and `tests/fixtures/` to that. It reads each line as written, each YAML or JSON key and string value as decoded (a fixture case given as codepoints as the text they spell), and each file's path, and fails on an advisory identifier or an advisory URL: the CVE and GHSA forms, OSV database ids, distribution and other security advisory ids, advisory database URLs, and any URL whose path names an advisory, a security bulletin or a product security response team. The forms are listed in [`tests/validate/advisory.go`](../tests/validate/advisory.go). A failure names the file, the line, the field where there is one and the kind of identifier, and prints `<advisory key>` in place of an identifier inside a path or a field name, so the run log does not repeat it.

The README shows an excerpt of one recorded run. `go run -mod=vendor ./capture` runs `go run -mod=vendor .`, writes the untrimmed output to [`captures/validate.txt`](captures/validate.txt) and a record of the run to [`captures/validate.json`](captures/validate.json), and rewrites the excerpt under the README's Validating section. The record holds the command, the `version` and `commit` of the merge base of HEAD and origin/main, the paths committed since that commit (`changedSinceCommit`), the uncommitted paths, the date, the exit code, and the line ranges the README shows. It names the merge base rather than HEAD because pull requests are squash merged: a commit made on a pull-request branch is not reachable from main after the merge, so a clone of main does not contain it, while the merge base is reachable from main. `go test -mod=vendor ./...` compares the recorded output with a fresh run and the README excerpt with the recorded lines, and checks that the recorded version resolves to the recorded commit and that the commit is reachable from origin/main, so a change to the signatures, the fixtures or the validator that changes the output needs a new capture.

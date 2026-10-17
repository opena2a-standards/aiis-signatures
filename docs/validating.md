# Validating

Run from the repository root:

```
cd tests/validate
go test -mod=vendor ./...
go run -mod=vendor .
```

The validator runs thirteen checks and exits non zero on any failure: schema validation, the id grammar, the family registry and layout, technique resolution, the canonical class, the attack vector, the exposure class, vocabulary disjointness, fixture presence, every fixture case through the matcher, the retired id list, the crosswalk, and the vendor manifests. A missing `provenance.source` or `provenance.first_seen` on an active signature prints a warning. `go run -mod=vendor . -write-crosswalk` regenerates `crosswalks/technique-signatures.json`.

The README shows an excerpt of one recorded run. `go run -mod=vendor ./capture` runs `go run -mod=vendor .`, writes the untrimmed output to [`captures/validate.txt`](captures/validate.txt) and a record of the run to [`captures/validate.json`](captures/validate.json), and rewrites the excerpt under the README's Validating section. The record holds the command, the `version` and `commit` of the merge base of HEAD and origin/main, the paths committed since that commit (`changedSinceCommit`), the uncommitted paths, the date, the exit code, and the line ranges the README shows. It names the merge base rather than HEAD because pull requests are squash merged: a commit made on a pull-request branch is not in the repository after the merge, the merge base is. `go test -mod=vendor ./...` compares the recorded output with a fresh run and the README excerpt with the recorded lines, and checks that the recorded version resolves to the recorded commit and that the commit is reachable from origin/main, so a change to the signatures, the fixtures or the validator that changes the output needs a new capture.

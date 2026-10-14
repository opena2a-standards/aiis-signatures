# Validating

Run from the repository root:

```
cd tests/validate
go test -mod=vendor ./...
go run -mod=vendor .
```

The validator runs thirteen checks and exits non zero on any failure: schema validation, the id grammar, the family registry and layout, technique resolution, the canonical class, the attack vector, the exposure class, vocabulary disjointness, fixture presence, every fixture case through the matcher, the retired id list, the crosswalk, and the vendor manifests. A missing `provenance.source` or `provenance.first_seen` on an active signature prints a warning. `go run -mod=vendor . -write-crosswalk` regenerates `crosswalks/technique-signatures.json`.

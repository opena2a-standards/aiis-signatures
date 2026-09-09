// Prints vendor/hackmyagent/check-ids.json: the sorted union of the keys of
// getTaxonomyMap() and the members of TAXONOMY_EXEMPT_CHECKIDS from the
// published hackmyagent package's dist/hardening/taxonomy.js.
//
// Usage:
//   npm pack hackmyagent@<version> --pack-destination <dir>
//   tar xzf <dir>/hackmyagent-<version>.tgz -C <dir>
//   node vendor/hackmyagent/generate.mjs <dir>/package > vendor/hackmyagent/check-ids.json
//
// The argument is the extracted package directory (the one holding
// package.json). Output is stable: sorted, two space indent, trailing newline.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: node generate.mjs <extracted hackmyagent package dir>");
  process.exit(2);
}
const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(resolve(dir, "package.json"), "utf8"));
const taxonomy = require(resolve(dir, "dist/hardening/taxonomy.js"));

const ids = new Set(Object.keys(taxonomy.getTaxonomyMap()));
for (const id of taxonomy.TAXONOMY_EXEMPT_CHECKIDS) ids.add(id);
const sorted = [...ids].sort();

const out = {
  package: pkg.name,
  version: pkg.version,
  count: sorted.length,
  checkIds: sorted,
};
process.stdout.write(JSON.stringify(out, null, 2) + "\n");

// Lab: per-case accept matrix for a small corpus. Usage: node matrix.mjs DIR
import { readFileSync, existsSync } from "node:fs";
const d = process.argv[2]; const r = {};
for (const f of ["rs", "node", "sodium", "bun", "py", "go"]) {
  if (!existsSync(`${d}/${f}.json`)) continue;
  for (const [k, v] of Object.entries(JSON.parse(readFileSync(`${d}/${f}.json`, "utf8")))) Object.assign((r[k] ??= {}), v);
}
const cs = JSON.parse(readFileSync(`${d}/corpus.json`, "utf8"));
const im = Object.keys(r[cs[0].id]);
console.log("| impl | " + cs.map((c) => c.id.split("|")[1]).join(" | ") + " |");
console.log("|---|" + cs.map(() => "---").join("|") + "|");
for (const i of im) console.log(`| ${i} | ` + cs.map((c) => (r[c.id][i] ? "**accept**" : "reject")).join(" | ") + " |");

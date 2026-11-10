// Lab: merge per-language accept bits and tabulate against ENV-210/211. Usage: node analyse.mjs OUTDIR
import { readFileSync, existsSync, writeFileSync } from "node:fs";

const dir = process.argv[2];
const cases = JSON.parse(readFileSync(`${dir}/corpus.json`, "utf8"));
const res = {};
for (const f of ["rs", "node", "sodium", "precheck", "bun", "py", "go"]) {
  const p = `${dir}/${f}.json`;
  if (!existsSync(p)) continue;
  const r = JSON.parse(readFileSync(p, "utf8"));
  for (const [id, m] of Object.entries(r)) Object.assign((res[id] ??= {}), m);
}
const REF = "rs:ENV-210/211 (audit-vectors)";
const impls = Object.keys(res[cases[0].id]);
const out = [];
const p = (s) => out.push(s);

// collapse class indices: A:mixed[3] -> A:mixed, A:small-nc[..] -> A:small-nc
const kind = (c) => {
  if (c.class === "honest" || c.class.startsWith("speccheck")) return c.class;
  const [a, r, s] = c.class.split("|").map((x) => x.replace(/\[.*\]/, ""));
  return `${a} ${r} ${s} cofactorless=${c.f.eq_cofactorless ? "y" : "n"}`;
};

// 1. summary per implementation
p("## Per implementation (adversarial = all non-honest, non-speccheck cases)\n");
p("| Implementation | honest rejected | adversarial accepted | accepts where ENV-210/211 rejects | rejects where ENV-210/211 accepts |");
p("|---|---|---|---|---|");
const adv = cases.filter((c) => c.class !== "honest" && !c.class.startsWith("speccheck"));
const hon = cases.filter((c) => c.class === "honest");
p(`(${hon.length} honest, ${adv.length} adversarial cases)\n`.replace(/^/, "<!-- ") + " -->");
for (const i of impls) {
  const hr = hon.filter((c) => !res[c.id][i]).length;
  const aa = adv.filter((c) => res[c.id][i]).length;
  const fa = adv.filter((c) => res[c.id][i] && !res[c.id][REF]).length;
  const fr = adv.filter((c) => !res[c.id][i] && res[c.id][REF]).length;
  p(`| ${i} | ${hr} / ${hon.length} | ${aa} / ${adv.length} | ${fa} | ${fr} |`);
}

// 2. per class kind
p("\n## Accepted / total per case kind\n");
const kinds = [...new Set(adv.map(kind))].sort();
const short = impls.map((i, n) => `I${n}`);
p("| kind | n | " + short.join(" | ") + " |");
p("|---|---|" + short.map(() => "---").join("|") + "|");
for (const k of kinds) {
  const cs = adv.filter((c) => kind(c) === k);
  const cells = impls.map((i) => {
    const a = cs.filter((c) => res[c.id][i]).length;
    return a === 0 ? "·" : a === cs.length ? "all" : `${a}`;
  });
  p(`| ${k} | ${cs.length} | ${cells.join(" | ")} |`);
}
p("\n" + impls.map((i, n) => `I${n} = ${i}`).join("  \n"));

// 3. speccheck
p("\n## speccheck vectors 0–11 (Chalkias et al. 2020), V = accept\n");
p("| impl | " + [...Array(12).keys()].join(" | ") + " |");
p("|---|" + [...Array(12)].map(() => "---").join("|") + "|");
for (const i of impls) {
  p(`| ${i} | ` + [...Array(12).keys()].map((n) => (res[`speccheck|${n}`][i] ? "V" : "X")).join(" | ") + " |");
}

// 4. distinct behaviour classes (equivalence of accept vectors over the whole corpus)
p("\n## Implementations with identical accept sets over all cases\n");
const sig = (i) => cases.map((c) => (res[c.id][i] ? 1 : 0)).join("");
const groups = {};
for (const i of impls) (groups[sig(i)] ??= []).push(i);
for (const g of Object.values(groups)) p(`- ${g.join("; ")}`);

writeFileSync(`${dir}/tables.md`, out.join("\n") + "\n");
console.log(out.join("\n"));

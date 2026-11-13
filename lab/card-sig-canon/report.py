"""Aggregate verdicts. usage: python report.py OUTDIR"""
import collections, json, os, sys

O = sys.argv[1]
V = ["py_sdk", "js_sdk", "py_spec", "rs_raw", "rs_clean"]
cand = {}
for line in open(os.path.join(O, "candidates.jsonl")):
    c = json.loads(line); c.pop("wire"); cand[c["cid"]] = c
for f in ["verdict_py.jsonl", "verdict_js.jsonl", "verdict_rs.jsonl"]:
    for line in open(os.path.join(O, f)):
        v = json.loads(line); cand[v["cid"]].update({k: v[k] for k in v if k in V})


def pct(a, b):
    return f"{100 * a / b:5.1f} % ({a}/{b})" if b else "n/a"


out = []
p = out.append
p("## Baseline: served card, no mutation (accept rate)\n")
p("| signer | n | " + " | ".join(V) + " |")
p("|---|---|" + "---|" * len(V))
for s in ["py", "js", "rs"]:
    rows = [c for c in cand.values() if c["signer"] == s and c["mutation"] == "none"]
    p(f"| {s} | {len(rows)} | " + " | ".join(pct(sum(r[v] for r in rows), len(rows)) for v in V) + " |")

p("\n## Baseline rejections by card feature (cards with that feature, accept rate)\n")
feats = sorted({f for c in cand.values() for f in c["features"]} | {"(none)"})
p("| signer | feature | n | " + " | ".join(V) + " |")
p("|---|---|---|" + "---|" * len(V))
for s in ["py", "js", "rs"]:
    for f in feats:
        rows = [c for c in cand.values() if c["signer"] == s and c["mutation"] == "none"
                and (f in c["features"] or (f == "(none)" and not c["features"]))]
        if rows and any(sum(r[v] for r in rows) != len(rows) for v in V):
            p(f"| {s} | {f} | {len(rows)} | " + " | ".join(pct(sum(r[v] for r in rows), len(rows)) for v in V) + " |")

p("\n## Keyless mutations of a card that verified as served (accept rate)\n")
p("Only candidates whose unmutated card the verifier accepted are counted for that verifier.\n")
base = {(c["id"], c["signer"]): c for c in cand.values() if c["mutation"] == "none"}
muts = sorted({c["mutation"] for c in cand.values()} - {"none"}, key=lambda m: (m != "reserialize", m))
for s in ["py", "js", "rs"]:
    p(f"\n### signer = {s}\n")
    p("| mutation | " + " | ".join(V) + " |")
    p("|---|" + "---|" * len(V))
    for m in muts:
        rows = [c for c in cand.values() if c["signer"] == s and c["mutation"] == m]
        cells = []
        for v in V:
            ok = [r for r in rows if base[(r["id"], s)][v]]
            cells.append(pct(sum(r[v] for r in ok), len(ok)))
        p(f"| {m} | " + " | ".join(cells) + " |")
p("\n## Portable cards (rs-signed cards that rs_raw, rs_clean and py_spec all accept)\n")
port = {k for k, c in base.items() if k[1] == "rs" and c["rs_raw"] and c["rs_clean"] and c["py_spec"]}
n_rs = sum(1 for k in base if k[1] == "rs")
p(f"{len(port)} of {n_rs} rs-signed cards are portable: raw JCS = SDK-cleaned JCS = ProtoJSON-roundtrip JCS.\n")
p("| mutation | " + " | ".join(V) + " |")
p("|---|" + "---|" * len(V))
for m in ["none"] + muts:
    rows = [c for c in cand.values() if (c["id"], c["signer"]) in port and c["mutation"] == m]
    p(f"| {m} | " + " | ".join(pct(sum(r[v] for r in rows), len(rows)) for v in V) + " |")
txt = "\n".join(out)
open(os.path.join(O, "report.md"), "w").write(txt + "\n")
print(txt)

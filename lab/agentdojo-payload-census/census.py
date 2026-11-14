"""Census of dump.py output. usage: census.py file.json"""
import sys, json, collections, unicodedata
d = json.load(open(sys.argv[1]))
tot = err = emptyd = 0; payloads = collections.Counter(); sizes = []; nonascii = ctrl = 0; keys = collections.Counter()
per = {}
for s, v in d["suites"].items():
    c = v["cases"]; per[s] = (len({x["u"] for x in c}), len(v["injection_tasks"]), len(c))
    for x in c:
        tot += 1; inj = x["inj"]
        if "__error__" in inj: err += 1; continue
        if not inj: emptyd += 1; continue
        for k, p in inj.items():
            keys[k] += 1; payloads[p] += 1; b = p.encode(); sizes.append(len(b))
            if any(ord(ch) > 127 for ch in p): nonascii += 1
            if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in p): ctrl += 1
sizes.sort(); n = len(sizes)
print(sys.argv[1].split('/')[-1], "cases", tot, "err", err, "empty", emptyd, "slots", n, "distinct", len(payloads),
      "size min/p50/p95/max", sizes[0], sizes[n//2], sizes[int(n*.95)], sizes[-1], "nonascii", nonascii, "ctrl", ctrl)
print("  per suite (user,inj,cases):", per, " distinct slot keys:", len(keys))

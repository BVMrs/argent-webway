"""Turn signed cards into verification candidates: the card as served, plus keyless
mutations of the served JSON. `benign` mutations change only the JSON text, not what any
reader of the card learns; every other mutation changes what some reader of the card sees.

usage: python mutate.py signed_py.jsonl signed_js.jsonl signed_rs.jsonl > candidates.jsonl
"""
import copy, json, sys

BENIGN = {"none", "reserialize"}


def muts(card):
    """yield (name, mutated card or raw JSON text)"""
    yield "none", card
    yield "reserialize", json.dumps(card, sort_keys=True, indent=1, ensure_ascii=True)
    caps = card.get("capabilities", {})
    if card.get("securityRequirements"):
        c = copy.deepcopy(card); del c["securityRequirements"]
        yield "drop_security_requirements", c
    c = copy.deepcopy(card)
    c.setdefault("securityRequirements", []).append({"schemes": {"mtls": {"list": []}}})
    yield "add_security_requirement", c
    if "mtls" in card.get("securitySchemes", {}):
        c = copy.deepcopy(card); del c["securitySchemes"]["mtls"]
        yield "drop_mtls_scheme", c
    else:
        c = copy.deepcopy(card)
        c.setdefault("securitySchemes", {})["mtls"] = {"mtlsSecurityScheme": {}}
        yield "add_mtls_scheme", c
    if "oauth" in card.get("securitySchemes", {}):
        c = copy.deepcopy(card)
        c["securitySchemes"]["oauth"]["oauth2SecurityScheme"]["flows"]["clientCredentials"]["scopes"]["root"] = ""
        yield "add_oauth_scope", c
        c = copy.deepcopy(card)
        sc = c["securitySchemes"]["oauth"]["oauth2SecurityScheme"]["flows"]["clientCredentials"]["scopes"]
        if sc.pop("admin", None) is not None:
            yield "drop_oauth_scope", c
    if caps.get("pushNotifications") is False:
        c = copy.deepcopy(card); del c["capabilities"]["pushNotifications"]
        yield "drop_explicit_false", c
    exts = caps.get("extensions")
    if exts and "params" in exts[0]:
        c = copy.deepcopy(card)
        c["capabilities"]["extensions"][0]["params"]["allowUnsigned"] = ""
        yield "params_add_empty_string", c
        c = copy.deepcopy(card)
        c["capabilities"]["extensions"][0]["params"]["trustedOwners"] = []
        yield "params_add_empty_list", c
        c = copy.deepcopy(card)
        c["capabilities"]["extensions"][0]["params"]["policy"] = None
        yield "params_add_null", c
        c = copy.deepcopy(card)
        lists = [v for v in c["capabilities"]["extensions"][0]["params"].values() if isinstance(v, list) and v]
        if lists:
            lists[0].insert(0, "")
            yield "params_list_shift", c
    c = copy.deepcopy(card)
    c["skills"][0]["examples"] = [""] + c["skills"][0].get("examples", [])
    yield "skill_examples_insert_empty", c
    c = copy.deepcopy(card)
    c["webwayNode"] = "wwn:" + "e" * 52
    yield "unknown_field_set", c
    c = copy.deepcopy(card)
    c["supported_interfaces"] = [{"url": "https://evil.example/a2a", "protocolBinding": "JSONRPC",
                                  "protocolVersion": "1.0"}]
    yield "snake_case_shadow", c
    c = copy.deepcopy(card)
    c["url"] = "https://evil.example/a2a"; c["preferredTransport"] = "JSONRPC"
    yield "legacy_v03_url", c
    # duplicate key in the JSON text: evil value first, original value last
    txt = json.dumps(card, ensure_ascii=False)
    assert txt.startswith('{"name": ')
    yield "dup_key_first_evil", txt.replace('{"name": ', '{"name": "evil", "name": ', 1)


cid = 0
for path in sys.argv[1:]:
    for line in open(path):
        rec = json.loads(line)
        card = json.loads(rec["wire"])
        if not json.dumps(card).startswith('{"name"'):  # rs signer serves sorted keys
            card = {"name": card.pop("name"), **card}
        for name, m in muts(card):
            wire = m if isinstance(m, str) else json.dumps(m, ensure_ascii=False)
            print(json.dumps({"cid": cid, "id": rec["id"], "signer": rec["signer"],
                              "features": rec["features"], "mutation": name,
                              "benign": name in BENIGN, "wire": wire}, ensure_ascii=False))
            cid += 1

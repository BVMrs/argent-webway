"""Generate random A2A v1.0 Agent Cards (ProtoJSON, camelCase) with edge features.

usage: python gen.py N SEED > cards.jsonl
Each line: {"id": int, "features": [..], "card": {...}}
"""
import json, random, sys

N, SEED = int(sys.argv[1]), int(sys.argv[2])
rng = random.Random(SEED)
WORDS = ["alpha", "beta", "tests", "run", "plan", "Ωmega", "naïve", "日本", "😀x", "p", "a\"q", "tab\t", "z"]


def word():
    return rng.choice(WORDS)


def rand_json(depth=0):
    """Extension params: arbitrary JSON incl. empties, nulls and numbers."""
    r = rng.random()
    if depth > 2 or r < 0.45:
        return rng.choice([
            "", None, True, False, 0, 1, -7, 3.5, 1e21, 2 ** 53 + 1, 0.1,
            word(), "", [], {},
        ])
    if r < 0.7:
        return [rand_json(depth + 1) for _ in range(rng.randint(0, 4))]
    return {word() + str(i): rand_json(depth + 1) for i in range(rng.randint(0, 4))}


def card(i):
    feats = []
    c = {
        "name": f"agent-{i}",
        "description": "Runs tests for a peer",
        "supportedInterfaces": [{"url": f"https://a{i}.example/a2a", "protocolBinding": "JSONRPC",
                                 "protocolVersion": "1.0"}],
        "version": "1.0.0",
        "capabilities": {"streaming": True},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "run-tests", "name": "Run tests", "description": "Run a test suite",
                    "tags": ["ci"]}],
    }
    if rng.random() < 0.3:
        feats.append("opt_false")
        c["capabilities"]["pushNotifications"] = False
    if rng.random() < 0.1:
        feats.append("opt_empty_str")
        c["documentationUrl"] = ""
    if rng.random() < 0.3:
        feats.append("bearer_no_scopes")
        c.setdefault("securitySchemes", {})["bearer"] = {"httpAuthSecurityScheme": {"scheme": "Bearer"}}
        c.setdefault("securityRequirements", []).append({"schemes": {"bearer": {"list": []}}})
    if rng.random() < 0.15:
        feats.append("mtls_scheme")
        c.setdefault("securitySchemes", {})["mtls"] = {"mtlsSecurityScheme": {}}
    if rng.random() < 0.15:
        feats.append("oauth_empty_scope_desc")
        c.setdefault("securitySchemes", {})["oauth"] = {"oauth2SecurityScheme": {"flows": {
            "clientCredentials": {"tokenUrl": "https://idp.example/t",
                                  "scopes": {"read": "Read access", "admin": ""}}}}}
    if rng.random() < 0.5:
        feats.append("ext_params")
        c["capabilities"]["extensions"] = [{
            "uri": "https://webway.example/ext/envelope/v0", "required": True,
            "params": {"k" + str(j): rand_json() for j in range(rng.randint(1, 4))}}]
    if rng.random() < 0.2:
        feats.append("unknown_field")
        c["webwayNode"] = "wwn:" + "a" * 52
    if rng.random() < 0.2:
        feats.append("non_bmp")
        c["name"] = "agent 😀 " + word()
        c["skills"][0]["tags"].append("")
    if rng.random() < 0.1:
        feats.append("empty_list_item")
        c["skills"][0]["examples"] = ["", "run the suite"]
    return {"id": i, "features": feats, "card": c}


for i in range(N):
    print(json.dumps(card(i), ensure_ascii=False))

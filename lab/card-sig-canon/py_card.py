"""Python a2a-sdk side: sign cards with the SDK, verify candidates two ways.

usage:
  python py_card.py sign  < cards.jsonl      > signed_py.jsonl
  python py_card.py verify < candidates.jsonl > verdict_py.jsonl

verify emits, per candidate, two verdicts:
  py_sdk  : client.card_resolver.parse_agent_card + utils.signing verifier (the SDK path)
  py_spec : A2A §8.4.1 read literally: MessageToDict (proto presence rules), drop
            `signatures`, JCS, no recursive empty-value cleaning
"""
import json, sys, warnings, logging
warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from google.protobuf.json_format import MessageToDict
import jwt
from a2a.types import AgentCard
from a2a.client.card_resolver import parse_agent_card
from a2a.utils.signing import create_agent_card_signer, create_signature_verifier
from a2a.utils._jcs import canonicalize
from a2a.server.request_handlers.response_helpers import agent_card_to_dict
from keys import SEED_HEX, PUB_HEX

priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUB_HEX))


def sign():
    signer = create_agent_card_signer(priv, {"alg": "EdDSA", "kid": "owner-b", "typ": "JOSE"})
    for line in sys.stdin:
        rec = json.loads(line)
        card = parse_agent_card(json.loads(json.dumps(rec["card"])))
        signed = signer(card)
        served = agent_card_to_dict(signed)  # what the SDK's /.well-known route serves
        print(json.dumps({"id": rec["id"], "signer": "py", "features": rec["features"],
                          "wire": json.dumps(served, ensure_ascii=False)}, ensure_ascii=False))


def spec_verify(card):
    d = MessageToDict(card)
    sigs = d.pop("signatures", [])
    payload = jwt.utils.base64url_encode(canonicalize(d).encode()).decode()
    for s in sigs:
        try:
            jwt.decode(f"{s['protected']}.{payload}.{s['signature']}", key=pub, algorithms=["EdDSA"])
            return True
        except Exception:
            pass
    return False


def verify():
    sdk = create_signature_verifier(lambda kid, jku: pub, ["EdDSA"])
    for line in sys.stdin:
        c = json.loads(line)
        out = {"cid": c["cid"]}
        try:
            card = parse_agent_card(json.loads(c["wire"]))
        except Exception as e:
            out.update(py_sdk=False, py_spec=False, py_err="parse:" + type(e).__name__)
            print(json.dumps(out)); continue
        try:
            sdk(card); out["py_sdk"] = True
        except Exception as e:
            out["py_sdk"] = False
        try:
            out["py_spec"] = spec_verify(card)
        except Exception as e:
            out["py_spec"] = False
        print(json.dumps(out))


{"sign": sign, "verify": verify}[sys.argv[1]]()

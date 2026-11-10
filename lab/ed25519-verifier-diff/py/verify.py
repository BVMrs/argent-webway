"""Lab: Python Ed25519 verifiers over the corpus (A2A python SDK interop: PyJWT -> cryptography).
Usage: python -I verify.py CORPUS OUT"""
import json, sys, time
import nacl.bindings
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.backends.openssl import backend

cases = json.load(open(sys.argv[1]))
ossl = backend.openssl_version_text()
res = {}
t = time.time()
for c in cases:
    pk, sig, msg = bytes.fromhex(c["pk"]), bytes.fromhex(c["sig"]), bytes.fromhex(c["msg"])
    r = {}
    try:
        nacl.bindings.crypto_sign_open(sig + msg, pk)
        r["py:PyNaCl 1.6.2 (bundled libsodium)"] = True
    except Exception:
        r["py:PyNaCl 1.6.2 (bundled libsodium)"] = False
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        r[f"py:cryptography 50 [{ossl}]"] = True
    except Exception:
        r[f"py:cryptography 50 [{ossl}]"] = False
    res[c["id"]] = r
print(f"python: {len(cases)} cases in {time.time()-t:.1f} s", file=sys.stderr)
json.dump(res, open(sys.argv[2], "w"))

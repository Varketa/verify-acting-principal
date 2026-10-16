"""The deployed-JWKS discovery check: run by hand (`python -m unittest tests/discovery_live.py`), never in CI.

It proves DISCOVERY interop with an issuer's deployed metadata and key set (issuer, jwks_uri, each key's kid, alg and
use, a max-age of at most 300 s), NOT a signature by that issuer's key. Its one negative: an assertion under a kid the
deployed set does not hold is refused `kid`, after one fresh refetch.
"""
import base64
import json
import os
import re
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from varketa_verify_acting_principal import METADATA_PATH, TYP, InMemoryReplayStore, VerificationError, Verifier
from varketa_verify_acting_principal import _default_fetch  # the library's own: no redirect, 10 s, 64 KiB

ISSUER = os.environ.get("VARKETA_ISSUER", "https://api.varketa.ai")


def get(url):
    r = _default_fetch(url)
    assert r.status == 200, url
    m = re.search(r"max-age=(\d+)", r.cache_control or "", re.I)
    assert m and int(m.group(1)) <= 300, f"{url} Cache-Control max-age must be at most 300 s"
    return json.loads(r.body)


def enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Discovery(unittest.TestCase):
    def test_the_deployed_metadata_and_key_set_are_what_the_spec_reads(self):
        md = get(ISSUER + METADATA_PATH)
        self.assertEqual(md["issuer"], ISSUER)
        self.assertIn(3, md["ver_values_supported"])
        self.assertTrue(md["jwks_uri"].startswith("https://"), md["jwks_uri"])
        self.assertTrue(set(md["signing_alg_values_supported"]) <= {"ES256", "ES384", "EdDSA"})
        keys = get(md["jwks_uri"])["keys"]
        self.assertGreaterEqual(len(keys), 1)
        for k in keys:
            self.assertIsInstance(k["kid"], str)
            self.assertIn(k["alg"], ("ES256", "ES384", "EdDSA"))
            self.assertEqual(k["use"], "sig")
            self.assertNotIn("d", k)

    def test_an_unknown_kid_is_refused_against_the_deployed_key_set(self):
        key = ec.generate_private_key(ec.SECP256R1())
        now = int(time.time())
        head = enc(json.dumps({"alg": "ES256", "kid": "discovery-check-unknown-kid", "typ": TYP}).encode())
        body = enc(json.dumps({"ver": 3, "iss": ISSUER, "iat": now, "exp": now + 60, "jti": f"d-{now}"}).encode())
        r, s = decode_dss_signature(key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        sig = enc(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        md = get(ISSUER + METADATA_PATH)
        fetches = []

        def counted(url):
            fetches.append(url)
            return _default_fetch(url)

        v = Verifier(issuer=ISSUER, adopter="discovery-check", audience="https://discovery-check.invalid",
                     replay_store=InMemoryReplayStore(single_instance=True), fetch_document=counted)
        with self.assertRaises(VerificationError) as e:
            v.verify(method="GET", url="https://discovery-check.invalid/", body=b"", assertion=f"{head}.{body}.{sig}")
        self.assertEqual(e.exception.code, "kid")
        self.assertEqual(fetches.count(md["jwks_uri"]), 2, "one load and one fresh refetch on the unknown kid")


if __name__ == "__main__":
    unittest.main()

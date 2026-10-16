import base64
import json
import threading
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from varketa_verify_acting_principal import FetchedDocument, InMemoryReplayStore, VerificationError, Verifier

DIR = Path(__file__).resolve().parents[2] / "vectors" / "v3"
MANIFEST = json.loads((DIR / "manifest.json").read_text())
JWKS = MANIFEST["config"]["issuer"] + "/.well-known/varketa-acting-principal/jwks.json"


def b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Harness:
    def __init__(self, case: dict) -> None:
        self.case, self.counts, self.now = case, {}, 0
        cfg = MANIFEST["config"]
        self.verifier = Verifier(issuer=cfg["issuer"], adopter=cfg["adopter"], audience=cfg["audience"],
                                 replay_store=InMemoryReplayStore(single_instance=True),
                                 clock=lambda: self.now, fetch_document=self.fetch)

    def fetch(self, url: str) -> FetchedDocument:
        rs = self.case["fetches"].get(url) or []
        i = self.counts.get(url, 0)
        self.counts[url] = i + 1
        if not rs:
            raise OSError(f"no scripted response for {url}")
        r = rs[min(i, len(rs) - 1)]
        body = json.dumps(r["body"]).encode() if "body" in r else b""
        return FetchedDocument(r["status"], r.get("cache_control"), body)

    def verify(self, step: dict):
        self.now = step["now"]
        req = step["request"]
        try:
            return self.verifier.verify(method=req["method"], url=req["url"], body=b64(req["body_b64url"]),
                                        assertion=step["assertion"]), ""
        except VerificationError as e:
            return None, e.code


class Vectors(unittest.TestCase):
    def test_the_case_set_is_the_manifests(self) -> None:
        self.assertEqual(sorted(p.stem for p in (DIR / "cases").glob("*.json")), sorted(MANIFEST["cases"]))

    def test_every_vector(self) -> None:
        for name in MANIFEST["cases"]:
            with self.subTest(vector=name):
                case = json.loads((DIR / "cases" / f"{name}.json").read_text())
                h = Harness(case)
                for i, step in enumerate(case["steps"]):
                    identity, code = h.verify(step)
                    want = step["expect"]
                    if want["accept"]:
                        self.assertEqual(code, "", f"step {i} refused")
                        self.assertEqual(identity, want["identity"], f"step {i} identity")
                    else:
                        self.assertEqual(code, want["code"], f"step {i} code")
                    if want.get("jwks_fetches"):
                        self.assertEqual(h.counts.get(JWKS), want["jwks_fetches"], f"step {i} key-set fetches")

    def test_of_two_concurrent_copies_exactly_one_is_accepted(self) -> None:
        case = json.loads((DIR / "cases" / "good.json").read_text())
        h = Harness(case)
        h.now = case["steps"][0]["now"]
        # Warm the key set with another accepted assertion, so the threads race on the replay store alone.
        warm = json.loads((DIR / "cases" / "previous-key.json").read_text())["steps"][0]
        self.assertEqual(h.verify(warm)[1], "")
        barrier, results = threading.Barrier(8), []

        def run() -> None:
            barrier.wait()
            results.append(h.verify(case["steps"][0])[1])

        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), [""] + ["replay"] * 7)

    def test_the_verifier_refuses_to_start_without_its_settings(self) -> None:
        cfg = MANIFEST["config"]
        store = InMemoryReplayStore(single_instance=True)
        ok = dict(issuer=cfg["issuer"], adopter=cfg["adopter"], audience=cfg["audience"], replay_store=store)
        Verifier(**ok)
        for k in ("issuer", "adopter", "audience", "replay_store"):
            with self.subTest(setting=k), self.assertRaisesRegex(ValueError, k):
                Verifier(**dict(ok, **{k: None if k == "replay_store" else ""}))
        with self.assertRaisesRegex(ValueError, "single instance"):
            InMemoryReplayStore()
        for issuer in ("http://api.varketa.ai", "https://api.varketa.ai/", "https://api.varketa.ai/x", "file:///etc/x"):
            with self.subTest(issuer=issuer), self.assertRaisesRegex(ValueError, "https:// origin"):
                Verifier(**dict(ok, issuer=issuer))
        for audience in ("http://api.example", "https://api.example/", "https://api.example/x", "https://user:pass@api.example", "https://api.example:99999"):
            with self.subTest(audience=audience), self.assertRaises(ValueError):
                Verifier(**dict(ok, audience=audience))

    def test_a_segment_with_a_trailing_newline_is_malformed(self) -> None:
        # "AAAA\n" is one the lenient decoder would decode (it drops the newline), so only the alphabet check refuses it.
        from varketa_verify_acting_principal import _b64url
        with self.assertRaises(VerificationError) as e:
            _b64url("AAAA\n")
        self.assertEqual(e.exception.code, "malformed")

    def test_the_replay_record_lives_through_the_last_accepted_second(self) -> None:
        case = json.loads((DIR / "cases" / "exp-within-skew.json").read_text())
        calls = []

        class Recording:
            def set_if_absent(self, key, ttl, now):
                calls.append(ttl)
                return True

        h = Harness(case)
        h.verifier._store = Recording()
        identity, code = h.verify(case["steps"][0])
        self.assertEqual((code, calls), ("", [1]))

    def test_each_document_expires_independently_at_max_age(self) -> None:
        for suffix in ("", "/jwks.json"):
            with self.subTest(document=suffix):
                case = json.loads((DIR / "cases" / "good.json").read_text())
                url = MANIFEST["config"]["issuer"] + "/.well-known/varketa-acting-principal" + suffix
                case["fetches"][url][0]["cache_control"] = "max-age=1"
                case["fetches"][url].append({"status": 503})
                h = Harness(case)
                step = case["steps"][0]
                self.assertEqual(h.verify(step)[1], "")
                previous = json.loads((DIR / "cases" / "previous-key.json").read_text())["steps"][0]
                self.assertEqual(h.verify(dict(previous, now=step["now"] + 1))[1], "jwks_unavailable")
                self.assertEqual(h.counts[url], 2)

    def test_discovery_that_expires_during_its_fetch_is_unavailable(self) -> None:
        case = json.loads((DIR / "cases" / "good.json").read_text())
        h = Harness(case)
        fetch = h.fetch

        def delayed(url):
            r = fetch(url)
            if url.endswith("jwks.json"):
                h.now += 2
            return FetchedDocument(r.status, "max-age=1", r.body)

        h.verifier._fetch = delayed
        self.assertEqual(h.verify(case["steps"][0])[1], "jwks_unavailable")

    def test_json_segments_require_utf8(self) -> None:
        from varketa_verify_acting_principal import _object
        for body in (b'{"a":"\xff"}', '{"a":1}'.encode("utf-16"), b'\xef\xbb\xbf{}'):
            with self.subTest(body=body), self.assertRaises(VerificationError):
                _object(body)

    def test_replay_store_releases_a_key_at_its_exclusive_ttl_boundary(self) -> None:
        store = InMemoryReplayStore(single_instance=True)
        self.assertTrue(store.set_if_absent("key", 2, 100))
        self.assertFalse(store.set_if_absent("key", 2, 101))
        self.assertTrue(store.set_if_absent("key", 2, 102))

    def test_integer_valued_json_numbers_are_not_fractional(self) -> None:
        case = json.loads((DIR / "cases" / "good.json").read_text())
        step = case["steps"][0]
        claims = json.loads(b64(step["assertion"].split(".")[1]))
        for field in ("ver", "iat", "exp"):
            claims[field] = float(claims[field])
        key = Ed25519PrivateKey.generate()

        def enc(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        head = enc(json.dumps({"typ": "varketa-acting-principal+jwt", "alg": "EdDSA", "kid": "test"}).encode())
        body = enc(json.dumps(claims).encode())
        sig = enc(key.sign(f"{head}.{body}".encode()))
        case["fetches"][JWKS][0]["body"]["keys"] = [{"kid": "test", "kty": "OKP", "crv": "Ed25519",
            "x": enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}]
        identity, code = Harness(case).verify(dict(step, assertion=f"{head}.{body}.{sig}"))
        self.assertEqual(code, "")
        self.assertEqual(identity, step["expect"]["identity"])


if __name__ == "__main__":
    unittest.main()

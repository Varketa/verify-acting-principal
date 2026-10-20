import base64
import json
import threading
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from varketa_verify_acting_principal import (SUPPORTED_VERSIONS, FetchedDocument, InMemoryReplayStore, VerificationError,
                                             Verifier)

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
# The current set, which the tests below the vectors also read.
DIR = VECTORS / "v4"
MANIFEST = json.loads((DIR / "manifest.json").read_text())
# Each accepted claim-set version's set, and the cases a later version supersedes, each with its reason. A superseded
# case is not skipped: its refusal no longer holds, so its first step must now be accepted.
SETS = (
    ("v4", {}),
    # v3's unknown-ver presents ver 4, unknown when v3 was cut and accepted since; v4's unknown-ver presents ver 5.
    ("v3", {"unknown-ver": "ver 4 is a known claim set since v4"}),
)
JWKS = MANIFEST["config"]["issuer"] + "/.well-known/varketa-acting-principal/jwks.json"


def b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Harness:
    def __init__(self, case: dict, manifest: dict = MANIFEST) -> None:
        self.case, self.counts, self.now = case, {}, 0
        cfg = manifest["config"]
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
        self.assertEqual(sorted(int(version[1:]) for version, _ in SETS), sorted(SUPPORTED_VERSIONS))
        for version, superseded in SETS:
            with self.subTest(set=version):
                manifest = json.loads((VECTORS / version / "manifest.json").read_text())
                self.assertEqual(sorted(p.stem for p in (VECTORS / version / "cases").glob("*.json")),
                                 sorted(manifest["cases"]))
                self.assertTrue(manifest["cases"], "an empty set proves nothing")
                self.assertEqual(f"v{manifest['claim_set_ver']}", version)
                for name in superseded:
                    self.assertIn(name, manifest["cases"])

    def test_every_vector(self) -> None:
        for version, superseded in SETS:
            manifest = json.loads((VECTORS / version / "manifest.json").read_text())
            jwks = manifest["config"]["issuer"] + "/.well-known/varketa-acting-principal/jwks.json"
            for name in manifest["cases"]:
                with self.subTest(set=version, vector=name):
                    case = json.loads((VECTORS / version / "cases" / f"{name}.json").read_text())
                    h = Harness(case, manifest)
                    if name in superseded:
                        self.assertEqual(h.verify(case["steps"][0])[1], "", f"superseded: {superseded[name]}")
                        continue
                    for i, step in enumerate(case["steps"]):
                        identity, code = h.verify(step)
                        want = step["expect"]
                        if want["accept"]:
                            self.assertEqual(code, "", f"step {i} refused")
                            self.assertEqual(identity, want["identity"], f"step {i} identity")
                        else:
                            self.assertEqual(code, want["code"], f"step {i} code")
                        if want.get("jwks_fetches"):
                            self.assertEqual(h.counts.get(jwks), want["jwks_fetches"], f"step {i} key-set fetches")

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
        identity, code = _resigned(lambda c: c.update({f: float(c[f]) for f in ("ver", "iat", "exp")}))
        self.assertEqual(code, "")
        self.assertEqual(identity, json.loads((DIR / "cases" / "good.json").read_text())["steps"][0]["expect"]["identity"])

    def test_a_present_sub_id_is_exactly_iss_sub(self) -> None:
        # Shapes no vector carries: a fourth member, null, an array, a non-string subject. And one sub_id on ver 3, which
        # is judged as on ver 4.
        good = {"format": "iss_sub", "iss": "https://idp.adopter.example", "sub": "user-8812"}
        for sub_id, ver, want in ((dict(good, email="user@adopter.example"), 4, "malformed"), (None, 4, "malformed"),
                                  ([good], 4, "malformed"), (dict(good, sub=8812), 4, "malformed"),
                                  (dict(good, iss=""), 3, "malformed"), (good, 3, "")):
            with self.subTest(sub_id=sub_id, ver=ver):
                identity, code = _resigned(lambda c: c.update(sub_id=sub_id, ver=ver))
                self.assertEqual(code, want)
                if not want:
                    self.assertEqual(identity["sub_id"], good)


    def test_an_assertion_refused_for_its_sub_id_leaves_its_jti_unrecorded(self) -> None:
        # The sub_id check runs before the replay record: the same jti, well formed, is then accepted.
        bad, good = _resign_both(lambda c: c.update(sub_id={"format": "email"}), lambda c: None)
        self.assertEqual((bad, good), ("malformed", ""))

    def test_json_nested_past_the_recursion_limit_is_malformed(self) -> None:
        head = base64.urlsafe_b64encode(b"[" * 100000).rstrip(b"=").decode()
        self.assertEqual(Harness({"fetches": {}}).verify({"now": 0, "request": {"method": "GET", "url": "https://x",
            "body_b64url": ""}, "assertion": f"{head}.e30.AAAA"})[1], "malformed")

    def test_a_number_past_the_safe_integers_is_absent(self) -> None:
        # As in the JavaScript verifier: 2^60 is not a safe integer, so exp is absent and the refusal is expired.
        self.assertEqual(_resigned(lambda c: c.update(exp=2**60))[1], "expired")
        self.assertEqual(_resigned(lambda c: c.update(exp=float(2**60)))[1], "expired")

    def test_max_age_past_int_digit_limit_is_the_cap(self) -> None:
        from varketa_verify_acting_principal import _max_age
        for header, want in (("max-age=" + "9" * 5000, 300), ("max-age=" + "0" * 5000 + "5", 5), ("max-age=0", 0),
                             ("max-age=301", 300), ("max-age=0300", 300), ("no-cache", 0),
                             ("no-cache, \tMAX-AGE=120", 120), ("max-age=\u0663\u0660\u0660", 0),
                             ("no-cache,\x85max-age=120", 0), ("\xa0max-age=120", 0)):
            with self.subTest(header=header[:20]):
                self.assertEqual(_max_age(header), want)

    def test_the_default_fetch_ends_at_its_deadline_whatever_the_answer_does(self) -> None:
        # SPEC §2.5: the whole fetch is bounded, not each read. An answer that drips a byte every 50 ms never trips a
        # per-read timeout; it must still be cut off at the deadline (shortened here to 0.5 s), and its worker must end
        # soon after. A fast answer through the same path is the positive control.
        import time as _time
        import urllib.request
        from unittest import mock
        import varketa_verify_acting_principal as vap

        class Answer:
            def __init__(self, chunks, delay):
                self.chunks, self.delay, self.status, self.headers = chunks, delay, 200, {"Cache-Control": "max-age=60"}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read1(self, n):
                _time.sleep(self.delay)
                return self.chunks.pop(0) if self.chunks else b""

        def opener_for(answer):
            class Opener:
                def open(self, req, timeout):
                    return answer
            return lambda *handlers: Opener()

        with mock.patch.object(vap, "_FETCH_TIMEOUT", 0.5):
            with mock.patch.object(urllib.request, "build_opener", opener_for(Answer([b"x"] * 10_000, 0.05))):
                started = _time.monotonic()
                with self.assertRaises(TimeoutError):
                    vap._default_fetch("https://issuer.example/jwks.json")
                elapsed = _time.monotonic() - started
                self.assertGreaterEqual(elapsed, 0.45)
                self.assertLess(elapsed, 1.0, "the fetch outlived its deadline")
                for _ in range(40):
                    if not any(t.name == "varketa-verify-fetch" for t in threading.enumerate()):
                        break
                    _time.sleep(0.05)
                self.assertFalse(any(t.name == "varketa-verify-fetch" for t in threading.enumerate()),
                                 "the fetch's worker is still running after its deadline")
            # One read that blocks past the deadline (a stalled socket, within its own per-read timeout): the worker
            # cannot check the clock until it returns, so only the caller's wait bounds the fetch.
            with mock.patch.object(urllib.request, "build_opener", opener_for(Answer([b"x"], 3.0))):
                started = _time.monotonic()
                with self.assertRaises(TimeoutError):
                    vap._default_fetch("https://issuer.example/jwks.json")
                self.assertLess(_time.monotonic() - started, 1.0, "a stalled read held the fetch past its deadline")
            with mock.patch.object(urllib.request, "build_opener", opener_for(Answer([b'{"keys":', b"[]}"], 0))):
                doc = vap._default_fetch("https://issuer.example/jwks.json")
                self.assertEqual((doc.status, doc.cache_control, doc.body), (200, "max-age=60", b'{"keys":[]}'))
            with mock.patch.object(urllib.request, "build_opener", opener_for(Answer([b"x" * 8192] * 9, 0))), \
                    self.assertRaisesRegex(ValueError, "over 65536 bytes"):
                vap._default_fetch("https://issuer.example/jwks.json")

    def test_a_verify_whose_key_is_cached_never_waits_behind_a_slow_fetch(self) -> None:
        # The discovery runs outside the verifier's lock: while one verify waits on the refetch an unknown kid starts,
        # another whose key is cached and fresh is answered at once.
        case = json.loads((DIR / "cases" / "good.json").read_text())
        h = Harness(case)
        h.verify(case["steps"][0])
        release, started = threading.Event(), threading.Event()
        fetch = h.fetch

        def slow(url):
            if url == JWKS:
                started.set()
                release.wait(5)
            return fetch(url)

        h.verifier._fetch = slow

        def enc(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        unknown = enc(json.dumps({"typ": "varketa-acting-principal+jwt", "alg": "EdDSA", "kid": "rotated-in"}).encode())
        step = case["steps"][0]
        results = {}
        refetching = threading.Thread(
            target=lambda: results.setdefault("refetch", h.verify(dict(step, assertion=f"{unknown}.e30.AAAA"))[1]))
        refetching.start()
        self.assertTrue(started.wait(5), "the unknown kid started no refetch")
        warm = json.loads((DIR / "cases" / "previous-key.json").read_text())["steps"][0]
        cached = threading.Thread(target=lambda: results.setdefault("cached", h.verify(warm)[1]))
        cached.start()
        cached.join(2)
        self.assertFalse(cached.is_alive(), "a verify whose key is cached waited behind the refetch")
        self.assertEqual(results.get("cached"), "")
        # A second unknown-kid verify joins the refetch under way instead of answering before it lands.
        second = threading.Thread(
            target=lambda: results.setdefault("second", h.verify(dict(step, assertion=f"{unknown}.e30.AAAA"))[1]))
        second.start()
        second.join(0.3)
        self.assertTrue(second.is_alive(), "a verify for a kid the refetch under way may bring did not wait for it")
        release.set()
        refetching.join(5)
        second.join(5)
        self.assertEqual((results.get("refetch"), results.get("second")), ("kid", "kid"))
        self.assertEqual(h.counts[JWKS], 2, "one load and one shared refetch")

    def test_a_failed_refetch_keeps_a_fresh_key_set(self) -> None:
        # SPEC §2.3 refuses only after expiry: an unknown kid's refetch that fails (here a 503) answers that kid `kid`,
        # and the still-fresh set keeps verifying the kids it holds.
        case = json.loads((DIR / "cases" / "good.json").read_text())
        case["fetches"][JWKS].append({"status": 503})
        h = Harness(case)
        self.assertEqual(h.verify(case["steps"][0])[1], "")

        def enc(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        unknown = enc(json.dumps({"typ": "varketa-acting-principal+jwt", "alg": "EdDSA", "kid": "rotated-in"}).encode())
        self.assertEqual(h.verify(dict(case["steps"][0], assertion=f"{unknown}.e30.AAAA"))[1], "kid")
        self.assertEqual(h.counts[JWKS], 2, "the unknown kid refetched once, and the refetch failed")
        warm = json.loads((DIR / "cases" / "previous-key.json").read_text())["steps"][0]
        self.assertEqual(h.verify(warm)[1], "", "the failed refetch discarded the fresh key set")

def _resigned(change):
    """good's first step, its claims changed by change and signed again under a key the case's key set then carries."""
    case, step, sign = _signing_harness()
    return case.verify(dict(step, assertion=sign(change)))


def _resign_both(first, second):
    """Two re-signings of good's first step, verified in order by ONE verifier; their two refusal codes."""
    case, step, sign = _signing_harness()
    return case.verify(dict(step, assertion=sign(first)))[1], case.verify(dict(step, assertion=sign(second)))[1]


def _signing_harness():
    case = json.loads((DIR / "cases" / "good.json").read_text())
    step = case["steps"][0]
    key = Ed25519PrivateKey.generate()

    def enc(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def sign(change):
        claims = json.loads(b64(step["assertion"].split(".")[1]))
        change(claims)
        head = enc(json.dumps({"typ": "varketa-acting-principal+jwt", "alg": "EdDSA", "kid": "test"}).encode())
        body = enc(json.dumps(claims).encode())
        return f"{head}.{body}.{enc(key.sign(f'{head}.{body}'.encode()))}"

    case["fetches"][JWKS][0]["body"]["keys"] = [{"kid": "test", "kty": "OKP", "crv": "Ed25519",
        "x": enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}]
    return Harness(case), step, sign

if __name__ == "__main__":
    unittest.main()

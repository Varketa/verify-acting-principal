"""Verify the Varketa-Acting-Principal header, claim set versions 3 and 4.

The normative half is SPEC.md and vectors/v4 at the repository root; this module follows the spec's order.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

__all__ = [
    "HEADER", "TYP", "SUPPORTED_VERSIONS", "METADATA_PATH", "VerificationError", "FetchedDocument", "ReplayStore",
    "InMemoryReplayStore", "Verifier",
]

HEADER = "Varketa-Acting-Principal"
TYP = "varketa-acting-principal+jwt"
SUPPORTED_VERSIONS = (3, 4)
METADATA_PATH = "/.well-known/varketa-acting-principal"
_ALGORITHMS = {
    "ES256": (hashes.SHA256, "EC", "P-256", ec.SECP256R1, 32),
    "ES384": (hashes.SHA384, "EC", "P-384", ec.SECP384R1, 48),
    "EdDSA": (None, "OKP", "Ed25519", None, 0),
}
_SKEW = 60
_MAX_SAFE_INTEGER = 2**53 - 1
_MAX_LIFETIME = 120
_MAX_CACHE = 300
_REFETCH_INTERVAL = 60
_FETCH_TIMEOUT = 10
_MAX_DOCUMENT_BYTES = 64 * 1024
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


class VerificationError(Exception):
    """A refusal. `code` is one of the spec's codes, in its order."""

    def __init__(self, code: str, message: Optional[str] = None) -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class FetchedDocument:
    status: int
    cache_control: Optional[str]
    body: bytes


class ReplayStore(Protocol):
    def set_if_absent(self, key: str, ttl_seconds: int, now: int) -> bool:
        """Insert `key` with a time to live and report whether THIS call inserted it, in one atomic step: of two
        concurrent calls with one key, exactly one returns True. Never a read followed by a write."""


class _Flight:
    """One discovery in flight. Every verify that needs it waits on `done`, then reads `ok`."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.ok = False


class InMemoryReplayStore:
    """An in-process replay store. It is correct only for an API served by ONE instance, so it must be asked for."""

    def __init__(self, *, single_instance: bool = False) -> None:
        if single_instance is not True:
            raise ValueError("InMemoryReplayStore is for a single instance only: pass single_instance=True, "
                             "or supply a shared store")
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()
        self._inserts = 0

    def set_if_absent(self, key: str, ttl_seconds: int, now: int) -> bool:
        with self._lock:
            until = self._seen.get(key)
            if until is not None and now < until:
                return False
            self._seen[key] = now + ttl_seconds
            # Expired records are swept every 1024 inserts, so the store holds about one assertion lifetime of jtis.
            self._inserts += 1
            if self._inserts % 1024 == 0:
                for k in [k for k, u in self._seen.items() if u <= now]:
                    del self._seen[k]
            return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _default_fetch(url: str) -> FetchedDocument:
    """Fetch one discovery document: no redirect, at most 64 KiB, and the whole fetch within 10 s (SPEC §2.5).

    urllib's own timeout bounds each socket operation, not the fetch, so an answer that arrives a few bytes at a time
    would never end. The fetch therefore runs in a worker thread that the caller waits on for the remaining time; the
    worker also checks the same deadline between reads, so it ends soon after (within one more socket timeout). The
    opener is urllib's own, so its proxy handling is kept.
    """
    if not url.startswith("https://"):
        raise ValueError(f"{url}: not an https URL")
    deadline = time.monotonic() + _FETCH_TIMEOUT
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            result["document"] = _fetch_until(url, deadline)
        except BaseException as e:  # noqa: BLE001 - handed to the caller, which fails closed
            result["error"] = e

    worker = threading.Thread(target=run, name="varketa-verify-fetch", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive():
        raise TimeoutError(f"{url}: no complete answer within {_FETCH_TIMEOUT} s")
    if "error" in result:
        raise result["error"]
    return result["document"]


def _fetch_until(url: str, deadline: float) -> FetchedDocument:
    """The worker's half of _default_fetch: open and read, giving up at the deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"{url}: no time left to fetch")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.build_opener(_NoRedirect).open(req, timeout=remaining) as r:  # noqa: S310 - https only
        chunks: list[bytes] = []
        size = 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{url}: no complete answer within {_FETCH_TIMEOUT} s")
            # read1: what one read of the socket returns, so a slow answer reaches the deadline check between reads.
            chunk = r.read1(min(8192, _MAX_DOCUMENT_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_DOCUMENT_BYTES:
                raise ValueError(f"{url}: document over {_MAX_DOCUMENT_BYTES} bytes")
        return FetchedDocument(r.status, r.headers.get("Cache-Control"), b"".join(chunks))


def _max_age(cache_control: Optional[str]) -> int:
    # HTTP's own grammar, as in the JavaScript verifier: optional whitespace is space or tab, and digits are ASCII.
    # Neither shorthand is used: Python's \s and \d take Unicode spaces and digits, and JavaScript's \s another set.
    m = re.search(r"(?:^|,)[ \t]*max-age=([0-9]+)", cache_control or "", re.IGNORECASE)
    if not m:
        return 0
    # Compared by length first: int() refuses a string of more than 4300 digits (CPython's integer-string limit, from
    # 3.11 and 3.10.7), and any value of more than three significant digits is over the cap anyway.
    digits = m.group(1).lstrip("0") or "0"
    return _MAX_CACHE if len(digits) > 3 else min(int(digits), _MAX_CACHE)


def _b64url(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL.fullmatch(s):
        raise VerificationError("malformed")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise VerificationError("malformed") from e


def _object(b: bytes) -> dict[str, Any]:
    try:
        v = json.loads(b.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        # RecursionError: JSON nested past the interpreter's limit, which an unsigned header can be.
        raise VerificationError("malformed") from e
    if not isinstance(v, dict):
        raise VerificationError("malformed")
    return v


def _public_key(jwk: dict[str, Any], alg: str) -> Any:
    _, kty, crv, curve, size = _ALGORITHMS[alg]
    if jwk.get("kty") != kty or jwk.get("crv") != crv or jwk.get("alg", alg) != alg:
        raise ValueError("key does not match alg")
    x = _b64url(jwk.get("x", ""))
    if curve is None:
        return ed25519.Ed25519PublicKey.from_public_bytes(x)
    y = _b64url(jwk.get("y", ""))
    if len(x) != size or len(y) != size:
        raise ValueError("bad coordinates")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve()).public_key()


class Verifier:
    def __init__(self, *, issuer: str, adopter: str, audience: str, replay_store: ReplayStore,
                 clock: Optional[Callable[[], int]] = None,
                 fetch_document: Optional[Callable[[str], FetchedDocument]] = None,
                 request_url: Optional[Callable[[str], str]] = None) -> None:
        for name, v in (("issuer", issuer), ("adopter", adopter), ("audience", audience)):
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"verify-acting-principal: {name} is required")
        if replay_store is None:
            raise ValueError("verify-acting-principal: replay_store is required (no silent default)")
        for name, value in (("issuer", issuer), ("audience", audience)):
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None \
                    or parsed.password is not None or f"https://{parsed.netloc}" != value \
                    or any(c.isspace() or c == "\\" for c in value):
                raise ValueError(f"verify-acting-principal: {name} must be an https:// origin")
            # Accessing port also refuses invalid or out-of-range ports at construction.
            parsed.port
        self._issuer, self._adopter, self._audience, self._store = issuer, adopter, audience, replay_store
        self._clock = clock or (lambda: int(time.time()))
        self._fetch = fetch_document or _default_fetch
        self._request_url = request_url or (lambda u: u)
        self._lock = threading.Lock()
        self._jwks_uri = ""
        self._md_fetched_at = self._md_max_age = 0
        self._keys: Optional[dict[str, dict[str, Any]]] = None
        self._fetched_at = self._max_age = 0
        self._last_refetch: Optional[int] = None
        # The discovery in flight, if any: fetched outside the lock, so a slow issuer never holds a verify whose key
        # is cached, and shared, so concurrent verifies that need it wait on one fetch.
        self._flight: Optional[_Flight] = None

    def _get(self, url: str) -> Optional[FetchedDocument]:
        try:
            r = self._fetch(url)
        except Exception:  # noqa: BLE001 - any failure to fetch is "unavailable", which fails closed
            return None
        return r if r.status == 200 else None

    def _load(self, now: int) -> bool:
        """One discovery: the fetches run outside the lock, and the result is published under it."""
        with self._lock:
            jwks_uri = self._jwks_uri
            need_metadata = not jwks_uri or now - self._md_fetched_at >= self._md_max_age
        metadata = None
        if need_metadata:
            md = self._get(self._issuer + METADATA_PATH)
            try:
                doc = _object(md.body) if md else None
            except VerificationError:
                doc = None
            if not doc or doc.get("issuer") != self._issuer or not isinstance(doc.get("jwks_uri"), str) \
                    or not doc["jwks_uri"].startswith("https://"):
                return False
            jwks_uri = doc["jwks_uri"]
            metadata = (jwks_uri, now, _max_age(md.cache_control))
        r = self._get(jwks_uri)
        try:
            keys = _object(r.body).get("keys") if r else None
        except VerificationError:
            keys = None
        with self._lock:
            if metadata:
                self._jwks_uri, self._md_fetched_at, self._md_max_age = metadata
            # A failed key-set fetch leaves the cache as it was: a fresh set stays usable until its max-age (SPEC §2.3
            # refuses only after expiry), so an unknown kid's refetch against a failing issuer cannot discard it.
            if not isinstance(keys, list):
                return False
            self._keys = {k["kid"]: k for k in keys if isinstance(k, dict) and isinstance(k.get("kid"), str)}
            self._fetched_at, self._max_age = now, _max_age(r.cache_control)
            return True

    def _stale(self, now: int) -> bool:
        return self._keys is None or now - self._fetched_at >= self._max_age \
            or now - self._md_fetched_at >= self._md_max_age

    def _flight_for(self, now: int, refetch: bool) -> tuple[Optional[_Flight], bool]:
        """Under the lock: the discovery to wait on and whether this caller leads it. A flight already under way is
        joined whatever its cause; a new one starts when the cache is stale, or for an unknown kid at most once a
        minute (SPEC §2.4)."""
        if self._flight is not None:
            return self._flight, False
        if refetch:
            if self._last_refetch is not None and now - self._last_refetch < _REFETCH_INTERVAL:
                return None, False
            self._last_refetch = now
        self._flight = _Flight()
        return self._flight, True

    def _fly(self, flight: _Flight, lead: bool, now: int) -> None:
        """Lead the discovery, or wait for the caller that leads it."""
        if not lead:
            flight.done.wait()
            return
        try:
            flight.ok = self._load(now)
        finally:
            with self._lock:
                self._flight = None
            flight.done.set()

    def _key_for(self, kid: str) -> Optional[dict[str, Any]]:
        # A stale cache: one discovery serves every verify that needs it, and a failed one refuses them all.
        with self._lock:
            now = self._clock()
            flight, lead = self._flight_for(now, refetch=False) if self._stale(now) else (None, False)
        if flight is not None:
            self._fly(flight, lead, now)
            if not flight.ok:
                raise VerificationError("jwks_unavailable")
        # An unknown kid: refetch once, or wait for a discovery already under way, which may bring it.
        with self._lock:
            now = self._clock()
            jwk = self._keys.get(kid) if self._keys else None
            flight, lead = self._flight_for(now, refetch=True) if jwk is None else (None, False)
        if flight is not None:
            self._fly(flight, lead, now)
        with self._lock:
            jwk = self._keys.get(kid) if self._keys else None
            # The clock again, after any wait: a discovery that expired during its fetch is unavailable.
            at = self._clock()
            if (self._md_max_age > 0 and at - self._md_fetched_at >= self._md_max_age) \
                    or (self._max_age > 0 and at - self._fetched_at >= self._max_age):
                raise VerificationError("jwks_unavailable")
            return jwk

    def verify(self, *, method: str, url: str, body: Union[bytes, str], assertion: Optional[str]) -> dict[str, Any]:
        """Verify one request's assertion and return the identity to authorize against, or raise VerificationError."""
        parts = (assertion or "").split(".")
        if len(parts) != 3:
            raise VerificationError("malformed")
        header = _object(_b64url(parts[0]))
        if header.get("typ") != TYP:
            raise VerificationError("typ")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in _ALGORITHMS:
            raise VerificationError("alg")
        jwk = self._key_for(header.get("kid") if isinstance(header.get("kid"), str) else "")
        if jwk is None:
            raise VerificationError("kid")
        signed, sig = f"{parts[0]}.{parts[1]}".encode(), _b64url(parts[2])
        try:
            key = _public_key(jwk, alg)
            digest, size = _ALGORITHMS[alg][0], _ALGORITHMS[alg][4]
            if digest is None:
                key.verify(sig, signed)
            else:
                if len(sig) != 2 * size:
                    raise InvalidSignature()
                der = encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
                key.verify(der, signed, ec.ECDSA(digest()))
        except (InvalidSignature, ValueError, TypeError, VerificationError) as e:
            # Any failure to build the published key, or to verify under it, is a signature failure, as in JS.
            raise VerificationError("signature") from e
        c = _object(_b64url(parts[1]))
        # The clock again, after any key-set wait: the time checks and the replay record's lifetime use it.
        at = self._clock()

        def s(k: str) -> Optional[str]:
            return c[k] if isinstance(c.get(k), str) else None

        def n(k: str) -> Optional[int]:
            v = c.get(k)
            # JSON 3.0 and 3e0 denote integers too, and only safe integers count (|v| <= 2^53 - 1), both as in the
            # JavaScript verifier's Number.isSafeInteger: a larger value is absent, so both verifiers refuse it alike.
            if isinstance(v, float) and v.is_integer():
                v = int(v)
            if not isinstance(v, int) or isinstance(v, bool) or abs(v) > _MAX_SAFE_INTEGER:
                return None
            return v

        iat, exp = n("iat"), n("exp")
        raw = body.encode() if isinstance(body, str) else bytes(body)
        bdy = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        if s("iss") != self._issuer:
            raise VerificationError("iss")
        if n("ver") not in SUPPORTED_VERSIONS:
            raise VerificationError("ver")
        if s("adopter") != self._adopter:
            raise VerificationError("adopter")
        if s("aud") != self._audience:
            raise VerificationError("aud")
        if iat is None or iat > at + _SKEW:
            raise VerificationError("not_yet_valid")
        if exp is None or at > exp + _SKEW:
            raise VerificationError("expired")
        if exp - iat > _MAX_LIFETIME:
            raise VerificationError("lifetime")
        if s("htm") != method:
            raise VerificationError("htm")
        if s("htu") != self._request_url(url):
            raise VerificationError("htu")
        if s("bdy") != bdy:
            raise VerificationError("bdy")
        jti, tenant = s("jti"), s("tenant")
        # The claims Varketa never omits and an API authorizes on: the jti, the tenant, and the subject or grant.
        if not jti or not tenant or not (s("sub") or s("grant")):
            raise VerificationError("malformed")
        # A PRESENT sub_id is exactly RFC 9493's iss_sub, its iss and sub non-empty strings, or the assertion is
        # malformed: a verifier never exposes half a subject.
        sub_id: Optional[dict[str, str]] = None
        if "sub_id" in c:
            v = c["sub_id"]
            if (not isinstance(v, dict) or len(v) != 3 or v.get("format") != "iss_sub"
                    or not isinstance(v.get("iss"), str) or not v["iss"]
                    or not isinstance(v.get("sub"), str) or not v["sub"]):
                raise VerificationError("malformed")
            sub_id = {"format": "iss_sub", "iss": v["iss"], "sub": v["sub"]}
        # LAST, after every other check: the record is the atomic step, an insert-if-absent on (iss, jti).
        # The record lives through the last accepted second, exp + 60 s inclusive: whole seconds, at least 1.
        if not self._store.set_if_absent(f"{self._issuer}\0{jti}", exp + _SKEW - at + 1, at):
            raise VerificationError("replay")
        identity: dict[str, Any] = {"tenant": tenant, "adopter": self._adopter}
        for k in ("sub", "grant", "persona", "act_kind", "presence", "run_id"):
            if s(k) is not None:
                identity[k] = s(k)
        if isinstance(c.get("scopes"), list):
            identity["scopes"] = [x for x in c["scopes"] if isinstance(x, str)]
        if "approved_by" in c:
            identity["approved_by"] = c["approved_by"]
        if c.get("probe") is True:
            identity["probe"] = True
        if sub_id is not None:
            identity["sub_id"] = sub_id
        return identity

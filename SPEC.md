# Verifying the Varketa acting principal (claim set versions 3 and 4)

When a Varketa agent calls your API, each request carries a `Varketa-Acting-Principal` header: a compact JWS that says
on whose behalf the call is made, for which of your customer orgs, and for exactly which request. This page is the
language-neutral specification. The [vectors](vectors/v4) are its normative half: a verifier that disagrees with a
vector is wrong. The libraries in this repository implement it.

Without verification your API sees only Varketa's service credential. It then cannot apply per-user or per-org
permissions, and its audit log names Varketa for every action.

## 1. Configure

A verifier REQUIRES three settings and refuses to start without any of them:

- **issuer**: Varketa's issuer, an `https://` origin with no path: `https://api.varketa.ai` in production. Refuse any
  other scheme: the key set is fetched from it, and in cleartext a network attacker would choose your keys.
- **adopter**: your API's adopter id, shown on Varketa's Tool sources page.
- **audience**: your API's own origin (`https://host[:port]`), the `aud` Varketa signs.

It also REQUIRES a replay store (§5). There is no silent default.

## 2. Discover the keys

1. Fetch `<issuer>/.well-known/varketa-acting-principal`. It is a JSON document naming `issuer` (equal to the
   configured issuer), `jwks_uri` (an `https://` URL), `ver_values_supported` and `signing_alg_values_supported`.
   Never fix the key path; it can move.
2. Fetch the JWK Set from `jwks_uri`. It holds the current key and, during a rotation, a second key. Both verify.
3. Cache each document for at most its `Cache-Control` max-age, capped at 300 s, and never past it. A refetch that
   fails after expiry refuses EVERY assertion (`jwks_unavailable`): no stale-if-error.
4. On a `kid` the cached set lacks, refetch the set once, at most once a minute, and refuse a `kid` still absent
   (`kid`).
5. Do not follow a redirect, and bound each fetch (the libraries use 10 s and 64 KiB): a stalled or oversized answer
   is a failed fetch.

## 3. Check, in this order

Refuse at the first failing check with its code. The order is normative: a vector can break more than one check, and
its code is the first one it breaks.

| # | Check | Code |
|---|---|---|
| 1 | The header is present, has three dot-separated parts, and its first is a base64url JSON object | `malformed` |
| 2 | `typ` is `varketa-acting-principal+jwt` | `typ` |
| 3 | `alg` is `ES256`, `ES384` or `EdDSA`; `none`, RSA and HMAC are refused | `alg` |
| 4 | The key set is fresh (§2.3) | `jwks_unavailable` |
| 5 | The `kid` is in the set (§2.4) | `kid` |
| 6 | The signature verifies under that key, whose type and curve match `alg` (a signature or claims part that is not base64url, or claims that are not a JSON object, is `malformed` here) | `signature` |
| 7 | `iss` equals the configured issuer | `iss` |
| 8 | `ver` is a version this verifier knows (3 or 4) | `ver` |
| 9 | `adopter` equals the configured adopter id | `adopter` |
| 10 | `aud` equals the configured audience | `aud` |
| 11 | `iat` is no more than 60 s after now | `not_yet_valid` |
| 12 | now is no more than 60 s after `exp` | `expired` |
| 13 | `exp − iat` is at most the assertion lifetime, 120 s | `lifetime` |
| 14 | `htm` equals the request method | `htm` |
| 15 | `htu` equals the request URL as the caller sent it (map it back through your proxies first) | `htu` |
| 16 | `bdy` equals the base64url (unpadded) SHA-256 of the raw body bytes | `bdy` |
| 17 | `jti` and `tenant` are present, and `sub` or `grant` is (Varketa never signs without them); a present `sub_id` is exactly an RFC 9493 `iss_sub` (§4) | `malformed` |
| 18 | The replay record (§5) | `replay` |

`ver`, `iat` and `exp` are integers; a fractional or non-numeric value is treated as absent, so it fails its check.

Why `adopter` matters: `aud` is the origin a Varketa tenant registered, and any tenant can register any origin. So a
valid Varketa signature with your `aud` can still be a call for ANOTHER adopter's source on the same origin. Only the
`adopter` check pins the call to yours.

Why the lifetime cap matters: without it, a leaked signing key could mint assertions that outlive the key's rotation.
A future `iat` within 60 s is honest clock skew and is accepted.

## 4. Use the identity

An accepted assertion exposes:

- `tenant`: **the org to authorize against**, your adopter org or one of its customer orgs. An API that serves
  customer orgs MUST authorize every record against `tenant`.
- `sub` and/or `grant`: the acting person or grant.
- `adopter`, `persona`, `scopes`, `act_kind` (`person`, `peer_run`, `automation_run`, `eval_run`), `presence`
  (`delegated`, `interactive`, `confirmed`), `run_id` (absent on a person's own act), `approved_by`.
- `sub_id` (claim set 4): the acting person as YOUR identity provider names them, an
  [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) subject identifier `{"format": "iss_sub", "iss": "<your IdP's
  issuer>", "sub": "<its subject>"}`. It is present when Varketa holds the acting grant's subject at your provider
  (recorded when the person signed in through it), and absent otherwise, never empty. Look your own user up by it
  instead of mapping Varketa's `sub`. A present `sub_id` has exactly those three members, `format`
  `iss_sub` and `iss` and `sub` non-empty strings, or the assertion is refused `malformed` (check 17): a verifier
  never exposes half a subject. It is judged the same way whatever the `ver`.
- `probe: true` on Varketa's verification probe only. A probe is verified like any other assertion, carries a fixed
  synthetic subject rather than a real person's, and reaches only a read. Act on no real data for it.

Authorization against these values is your own policy.

## 5. The replay record

Record `jti` only AFTER every other check passes, so a refused assertion's `jti` is never recorded. The record is the
atomic step: an insert-if-absent on (`iss`, `jti`) whose time to live covers the last accepted second, `exp` + 60 s
inclusive: `exp + 60 − now + 1` whole seconds, never less than 1. A conflict is a replay and is refused, so of two concurrent copies of one assertion exactly one is accepted. The store interface is set-if-absent,
never a read followed by a write.

An API served by more than one instance MUST supply a shared store (Redis `SET key 1 NX EX ttl`, or a unique-keyed
database insert). The libraries' in-memory store is correct for one instance only and must be asked for explicitly.

## 6. The vectors

`vectors/v<ver>/manifest.json` names the configuration every case runs under and the case list. Each
`vectors/v<ver>/cases/<name>.json` is one verifier's life:

- `fetches`: what each URL answers. The i-th fetch of a URL gets its i-th response, and the last one repeats. A
  missing `body` is an empty one.
- `steps`, in order, each with its clock (`now`, seconds since the epoch), the request (`method`, `url`,
  `body_b64url`), the `assertion` header value, and `expect`: `accept` with the exposed `identity`, or a refusal
  `code`. Where `jwks_fetches` is present, the JWK Set must have been fetched exactly that many times by then.

Run each case with a fresh verifier and a fresh in-memory store, the clock set to each step's `now`. The keys are
throwaway keys used only by the vectors.

A verifier passes the set of every claim-set version it accepts. One case in an older set can be superseded by a
newer version: `v3`'s `unknown-ver` presents `ver` 4, unknown when `v3` was cut, so a verifier that accepts 4 accepts
it. `v4`'s `unknown-ver` (`ver` 5) carries that check now.

## 7. Versions

`ver` 4 is the current claim set: claim set 3 plus `sub_id` (§4). A verifier accepts 3 and 4, and passes
`vectors/v4` and `vectors/v3` (§6). Each library release names the claim-set versions it accepts and the vector
version it passes. See [EVOLUTION.md](EVOLUTION.md).

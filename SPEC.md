# Verifying the Varketa acting principal (claim set versions 3, 4, 5 and 6)

When a Varketa agent calls your API, each request carries a `Varketa-Acting-Principal` header: a compact JWS that says
on whose behalf the call is made, for which of your customer orgs, and for exactly which request. This page is the
language-neutral specification. The [vectors](vectors) (one set per claim set, §6) are its normative half: a verifier
that disagrees with a vector is wrong. The libraries in this repository implement it.

Without verification your API sees only Varketa's service credential. It then cannot apply per-user or per-org
permissions, and its audit log names Varketa for every action.

## 1. Configure

A verifier REQUIRES three settings and refuses to start without any of them:

- **issuer**: Varketa's issuer, an `https://` origin with no path: `https://api.varketa.ai` in production. Refuse any
  other scheme: the key set is fetched from it, and in cleartext a network attacker would choose your keys.
  `https://app.dev.varketa.ai` is Varketa's development issuer, for building against Varketa's development
  deployment. It is NOT production: configure it only on a development or test instance of your API, never on the one
  your customers use. Its keys are discovered the same way (§2), from
  `https://app.dev.varketa.ai/.well-known/varketa-acting-principal`.
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
5. Do not follow a redirect, and bound each fetch as a whole, not each read (the libraries use 10 s and 64 KiB): a
   stalled, dripping or oversized answer is a failed fetch. Fetch outside any lock a verification of a cached key
   would wait on, so one slow issuer answer delays only the verifications that need it.

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
| 6 | The signature verifies under that key, whose type and curve match `alg` (a signature part that is not base64url is `malformed`, judged before the key's type; a claims part that is not base64url, or claims that are not a JSON object, is `malformed` once the signature verifies) | `signature` |
| 7 | `iss` equals the configured issuer | `iss` |
| 8 | `ver` is a version this verifier knows (3, 4, 5 or 6) | `ver` |
| 9 | `adopter` equals the configured adopter id | `adopter` |
| 10 | `aud` equals the configured audience | `aud` |
| 11 | `iat` is no more than 60 s after now | `not_yet_valid` |
| 12 | now is no more than 60 s after `exp` | `expired` |
| 13 | `exp − iat` is at most the assertion lifetime, 120 s | `lifetime` |
| 14 | `htm` equals the request method | `htm` |
| 15 | `htu` equals the request URL as the caller sent it (map it back through your proxies first) | `htu` |
| 16 | `bdy` equals the base64url (unpadded) SHA-256 of the raw body bytes | `bdy` |
| 17 | `jti` and `tenant` are present, and `sub` or `grant` is (Varketa never signs without them); a present `sub_id` is exactly an RFC 9493 `iss_sub` (§4); `act` is present exactly when `act_kind` is `on_behalf`, and is then exactly `{sub, iss}` (§4); a present `run_owner` is exactly `{sub}` or `{sub, sub_id}` beside a `run_id` (§4) | `malformed` |
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
- `adopter`, `persona`, `scopes`, `act_kind` (`person`, `peer_run`, `automation_run`, `eval_run`, from claim set 5
  `discovery` and `on_behalf`, and from claim set 6 `watch_run`, below), `presence` (`delegated`, `interactive`,
  `confirmed`), `run_id` (absent on a person's own act), `approved_by`.
- `act_kind` `discovery` (claim set 5): Varketa reading your API's own surface, such as an MCP `tools/list` or your
  OpenAPI document, to learn what it offers. It names no tool and no run. Its `sub` is `varketa-discovery` when no
  grant made the request; otherwise `grant` names the grant. Act on no customer's data for it.
- `act` (claim set 5, `act_kind` `on_behalf` only): a customer's own act that your backend performs through Varketa.
  `sub` is the customer, and `act` is the actor, an [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693#section-4.1)
  actor claim `{"sub": "<your backend's admission id>", "iss": "<the issuer that admission asserts>"}`; `presence` is
  `delegated`. A present `act` has exactly those two members, both non-empty strings. An `on_behalf` assertion
  without one, or an `act` on any other `act_kind`, is refused `malformed` (check 17): a verifier never exposes half
  an actor, nor an actor on a kind that has none.
- `act_kind` `watch_run` (claim set 6): a read inside a run of a customer's own standing watch. `run_id` names the
  check's run, `presence` is `delegated`, and `grant` names the grant; it carries no top-level `sub`. Varketa sends
  only reads for it.
- `run_owner` (claim set 6): the person accountable for the run, who defined the automation, requested the evaluation
  or created the watch. It is not the actor: `act_kind` says a run acted, and `presence` is `delegated`. Do not
  authorize it as the person present. It is `{"sub": "<subject>"}` or `{"sub": "<subject>", "sub_id": <iss_sub>}`.
  Its `sub` is the subject this adopter receives as `sub` on that person's own acts. Its `sub_id` is your own subject
  for the run-as grant, an exact `iss_sub` as below, present only where Varketa holds one. A present `run_owner` has
  exactly those members, `sub` a non-empty string, and only beside a `run_id`, or the assertion is refused `malformed`
  (check 17), whatever the `ver` or `act_kind`.
- `sub_id` (claim set 4): the acting person as YOUR identity provider names them, an
  [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) subject identifier `{"format": "iss_sub", "iss": "<your IdP's
  issuer>", "sub": "<its subject>"}`. It is present when Varketa holds the acting grant's subject at your provider
  (recorded when the person signed in through it), and absent otherwise, never empty. Look your own user up by it
  instead of mapping Varketa's `sub`, and by the pair: a `sub` is unique only within its `iss`, so match `iss` to an
  issuer you trust as well. A present `sub_id` has exactly those three members, `format`
  `iss_sub` and `iss` and `sub` non-empty strings, or the assertion is refused `malformed` (check 17): a verifier
  never exposes half a subject. It is judged the same way whatever the `ver`. On a run (`run_id` present), claim sets
  4 and 5 carry here the subject of the grant the run acts under, its owner, who is accountable for it and is not
  present; read `act_kind`. From claim set 6 a run carries it only inside `run_owner`.
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
newer version: each set's `unknown-ver` presents the next version, unknown when that set was cut, so a verifier that
accepts the next version accepts it. `v3`'s presents `ver` 4, `v4`'s `ver` 5 and `v5`'s `ver` 6; `v6`'s
`unknown-ver` (`ver` 7) carries that check now.

## 7. Versions

`ver` 6 is the current claim set: claim set 5 plus the `act_kind` value `watch_run` and `run_owner` (§4). Claim set 5
is claim set 4 plus the `act_kind` values `discovery` and `on_behalf`, and `act`; claim set 4 is claim set 3 plus
`sub_id`. A verifier accepts 3, 4, 5 and 6, and passes `vectors/v6`, `vectors/v5`, `vectors/v4` and `vectors/v3`
(§6). A reader that upgrades to 6 without reading `run_owner` loses `sub_id` on runs whose owner Varketa holds an
adopter subject for: read `run_owner` before you rely on `sub_id` for a run. Each library release names the
claim-set versions it accepts and the vector version it passes. See [EVOLUTION.md](EVOLUTION.md).

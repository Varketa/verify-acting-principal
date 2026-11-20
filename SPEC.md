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
  `https://app.dev.varketa.ai/.well-known/varketa-acting-principal`. Configure the exact published issuer spelling.
  The Python SDK rejects percent-escaped DNS hostnames, scope identifiers and noncanonical spellings in
  ordinary IPv6 literals, and numeric final labels outside canonical dotted-decimal IPv4. Earlier Python
  SDK versions could accept these issuer spellings at construction.
- **adopter**: your API's adopter id, shown on Varketa's Tool sources page.
- **audience**: your API's own origin (`https://host[:port]`), the `aud` Varketa signs.

It also REQUIRES a replay store (§5). There is no silent default.

## 2. Discover the keys

1. Fetch `<issuer>/.well-known/varketa-acting-principal`. It is a JSON document naming `issuer` (equal to the
   configured issuer), `jwks_uri` (an `https://` URL), `ver_values_supported` and `signing_alg_values_supported`.
   Never fix the key path; it can move.
2. Fetch the JWK Set from `jwks_uri`. It holds the current key and, during a rotation, a second key. Both verify.
3. Cache each document for at most its `Cache-Control` max-age, capped at 300 s, and never past it. A clock that
   reads earlier than a document's fetch is past its max-age, so a clock stepped back never keeps a document fresh. A
   refetch that fails after expiry refuses EVERY assertion (`jwks_unavailable`): no stale-if-error. After a discovery
   fails, start no new one for 15 s from that discovery's start, though one already in flight is joined. A
   verification that needs one in that time is refused (`jwks_unavailable`) without starting another discovery. One
   discovery can include both a metadata request and a JWKS request. A discovery that succeeds ends the failure
   floor.
4. On a `kid` the cached set lacks, refetch the set unless a refetch for an unknown `kid` started less than 15 s
   earlier (for any `kid`, whether or not it succeeded), and refuse a `kid` the set still lacks (`kid`). A refetch
   already in flight is joined, not repeated. The `kid` is read before the signature is checked, so any caller can
   start this refetch. The 15 s floor limits refetch starts on the verifier's clock. Verifying with a newly
   published key requires a fetched set containing it. A refetch takes time, and an in-flight response can return
   a set read before publication. Here and in §2.3, a clock that reads earlier than a floor's start is outside
   it, so a clock stepped back never holds a floor shut.
5. Do not follow a redirect, and bound each fetch as a whole, not each read (the libraries use 10 s and 64 KiB): a
   stalled, dripping or oversized answer is a failed fetch. Fetch outside any lock a verification of a cached key
   would wait on, so one slow issuer answer delays only the verifications that need it.

## 3. Check, in this order

Refuse at the first failing check with its code. The order is normative: a vector can break more than one check, and
its code is the first one it breaks.

These codes describe verification refusals, including failed key acquisition where §2 prescribes it. The SDK can
also propagate configuration, runtime and adopter callback failures as operational errors. A URL mapping that
returns a different URL fails check 15. A mapping that throws fails the operation without that verdict. The default
clocks return whole epoch seconds. Each custom JavaScript clock sample must be finite and each Python sample must
be an integer excluding booleans. An invalid sample is an operational error. The verifier does not substitute a clock.

| # | Check | Code |
|---|---|---|
| 1 | The header is present, has three dot-separated parts, and its first is a base64url JSON object | `malformed` |
| 2 | `typ` is `varketa-acting-principal+jwt` | `typ` |
| 3 | `alg` is `ES256`, `ES384` or `EdDSA`; `none`, RSA and HMAC are refused | `alg` |
| 4 | The key set is fresh (§2.3) | `jwks_unavailable` |
| 5 | The `kid` is in the set (§2.4) | `kid` |
| 6 | The signature verifies under that key. The key's type and curve match the protected header's `alg`, and the JWK's own `alg`, when present, matches it too. A signature part that is not base64url is `malformed`, judged before key compatibility. A claims part that is not base64url, or claims that are not a JSON object, is `malformed` once the signature verifies. | `signature` |
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
| 17 | `jti` and `tenant` are present, and `sub` or `grant` is (Varketa never signs without them); a present `sub_id` is exactly an RFC 9493 `iss_sub` (§4); `act_kind` is a non-empty string and a present `run_id` a nonblank string; `person`, `discovery` and `on_behalf` carry no `run_id`, and `peer_run`, `automation_run`, `eval_run` and `watch_run` carry one; `on_behalf` and `watch_run` have `presence` `delegated` (§4); `discovery` and `on_behalf` require claim set 5 or later, and `watch_run` and a present `run_owner` require claim set 6 or later; from claim set 6 an assertion containing `run_id` contains neither top-level `sub` nor `sub_id` (§4); `act` is present exactly when `act_kind` is `on_behalf`, and is then exactly `{sub, iss}` (§4); a present `run_owner` is exactly `{sub}` or `{sub, sub_id}` beside a `run_id` on an `automation_run`, `eval_run` or `watch_run` (§4); from claim set 6 a present `scope_id` is a string (§4); a present `approved_by` is a valid approval chain (§4) | `malformed` |
| 18 | The replay record (§5) | `replay` |

The protected header and claims each have a maximum JSON depth of 32, counting the root object as level 1.
Each nested object or array adds one level along its path, including empty containers and superseded members.
Strings and other scalars add no levels. An assertion extension deeper than this is refused as
`malformed` at check 1 for the header or at check 6 for claims after signature verification.
This limit applies to assertion JSON. Fetched metadata and JWK Sets use the fetch limits in §2.

In the protected header and claims objects, every member name and string value must contain only Unicode scalar values.
This includes nested, unrecognized and superseded member occurrences. A surrogate escape is allowed only in an adjacent
high–low pair. Such a pair and the equivalent literal UTF-8 character have the same decoded value. Compare names after
decoding without normalization. After scalar validation, a repeated name selects its last value. Refuse an unpaired
surrogate escape as `malformed` at check 1 for the header or at check 6 for claims after signature verification.

`ver`, `iat` and `exp` are integers; a fractional or non-numeric value is treated as absent, so it fails its check.

Supply the verifier with the exact request body bytes for check 16. Re-serializing JSON or converting the bytes
to text and back can change the hash. For a caller-supplied string, encode it as UTF-8 without replacement. A string
with an unpaired surrogate has no lossless UTF-8 encoding and is refused at check 16 with `bdy`.
This concerns the request body supplied to the verifier, separate from JSON decoding of the signed assertion.

Why `adopter` matters: `aud` is the origin a Varketa tenant registered, and any tenant can register any origin. So a
valid Varketa signature with your `aud` can still be a call for ANOTHER adopter's source on the same origin. Only the
`adopter` check pins the call to yours.

Why the lifetime cap matters: without it, a leaked signing key could mint assertions that outlive the key's rotation.
A future `iat` within 60 s is honest clock skew and is accepted.

## 4. Use the identity

An accepted assertion exposes:

- `tenant`: **the org to authorize against**, your adopter org or one of its customer orgs. An API that serves
  customer orgs MUST authorize every record against `tenant`.
- `sub` and/or `grant`: the acting person or grant. `sub` is opaque and scoped to you, the adopter: never compare it with a `sub` another adopter receives.
- `adopter`, `persona`, `scopes`, `act_kind` (`person`, `peer_run`, `automation_run`, `eval_run`, from claim set 5
  `discovery` and `on_behalf`, and from claim set 6 `watch_run`, below), `presence` (`delegated`, `interactive`,
  `confirmed`), `run_id` (absent on a person's own act), `approved_by`.
  Every accepted assertion states its act: `act_kind` is a non-empty string, and its run follows its kind, as Varketa's
  issuer signs it. `person`, `discovery` and `on_behalf` carry no `run_id`; `peer_run`, `automation_run`, `eval_run`
  and `watch_run` carry one, a string with at least one character outside Unicode 17.0 White_Space (as for
  `approved_by.sub`, below); `on_behalf` and `watch_run` have `presence` `delegated`. A kind this spec does not name
  passes, with or without a `run_id` (a nonblank string when present), and is exposed as signed: key your policy on the
  kinds you know. Any other shape is refused as `malformed` at check 17 before replay, at every claim set. This
  departs from earlier releases, which accepted an assertion with no `act_kind` in claim set 3 or 4: Varketa's issuer
  never signs one, so a verifier now refuses it rather than expose an act it cannot name.
  For an accepted claim-set version earlier than 5, `act_kind: "discovery"` or `act_kind: "on_behalf"` is
  refused as `malformed` at check 17 before replay, and so are `act_kind: "watch_run"` and a present `run_owner`
  at a version earlier than 6. Check 8 still refuses any unsupported version before this check.
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
  exactly those members, with a nonblank string `sub`, and is allowed only beside a `run_id` on an `automation_run`,
  `eval_run` or `watch_run`; check 17 refuses it as `malformed` otherwise, including below claim set 6.
- `sub_id` (claim set 4): the acting person as YOUR identity provider names them, an
  [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) subject identifier `{"format": "iss_sub", "iss": "<your IdP's
  issuer>", "sub": "<its subject>"}`. It is present when Varketa holds the acting grant's subject at your provider
  (recorded when the person signed in through it), and absent otherwise, never empty. Look your own user up by it
  instead of mapping Varketa's `sub`, and by the pair: a `sub` is unique only within its `iss`, so match `iss` to an
  issuer you trust as well. A present `sub_id` has exactly those three members, `format`
  `iss_sub` and `iss` and `sub` non-empty strings, or the assertion is refused `malformed` (check 17): a verifier
  never exposes half a subject. It is judged the same way whatever the `ver`. On a run (`run_id` present), claim sets
  4 and 5 carry here the subject of the grant the run acts under, its owner, who is accountable for it and is not
  present; read `act_kind`. From claim set 6 a run carries it only inside `run_owner`: an assertion containing
  `run_id` is refused at check 17 if a top-level `sub` or `sub_id` is present, even with a null value.
- `scope_id` (exposed from claim set 6): the Varketa scope inside `tenant` that the call was made at, as Varketa
  signed it: the org itself, or a scope within it. It is opaque: compare it only together with `tenant`, and still
  authorize every record against `tenant`. Record it, or apply your own policy to it. A verifier exposes it only as a
  non-empty string, and it is absent where Varketa signs no scope: on discovery, on the probe, and on any call made at
  no scope. From claim set 6 a present `scope_id` that is not a string is refused `malformed` (check 17). Claim sets 3
  to 5 sign it as well, and a verifier does not expose it there. Not signed: whether the scope is the org itself or a
  scope within it, and the scope's name.
- `probe: true` on Varketa's verification probe only. A probe is verified like any other assertion, carries a fixed
  synthetic subject rather than a real person's, and reaches only a read. Act on no real data for it.

When Varketa asserts an approval, it emits `approved_by` as a chain of up to eight links. Each link has a
string `sub` naming the approver's grant and, when another link follows, an `act` member containing that link.
The outermost `sub` identifies the approver selected for this apply. Varketa omits the claim when it has no
approver to report. The verifier leaves the claim absent in that case.

A present `approved_by` must be an object of one to eight links. Each decoded link has its own `sub`,
a string containing at least one character outside [Unicode 17.0 White_Space](https://www.unicode.org/Public/17.0.0/ucd/PropList.txt),
and only an optional `act` member containing the next link. The verifier exposes the accepted parsed chain unchanged,
including repeated grant values. It refuses any other shape as `malformed` at check 17 before recording replay.
Earlier verifier versions accepted some signed values outside this shape. The new check accepts the shape emitted by
the supported typed Varketa issuer. It does not establish whether the approvals were authorized or independent.

Varketa also signs, on a call to a tool, `tool_qualified` (the tool's name as Varketa qualifies it) and
`tool_declared` (its name as your API declares it). A verifier checks neither and does not expose them.

Authorization against these values is your own policy.

## 5. The replay record

Record `jti` only AFTER every other check passes, so a refused assertion's `jti` is never recorded. The record is the
atomic step: an insert-if-absent on (`iss`, `jti`) whose time to live covers the last accepted second, `exp` + 60 s
inclusive: `exp + 60 − now + 1` seconds, never less than 1. For a fractional JavaScript clock sample the computed TTL
may be fractional. Before the store call the JavaScript SDK requires a finite TTL and finite computed exclusive
expiry strictly after the computed inclusive cutoff. Unrepresentable retention is an operational error.

The store returns false for a conflict, which is refused as `replay`. Of two concurrent copies of one assertion
exactly one is accepted. The store interface is set-if-absent, never a read followed by a write. A storage failure
can leave the outcome unknown, for example if the acknowledgement is lost after insertion. In that case the store
raises an error. The verifier returns no identity and does not retry the insertion or interpret it as a conflict.

An API served by more than one instance MUST supply a shared store (Redis `SET key 1 NX EX ttl`, or a unique-keyed
database insert). The libraries' in-memory store is correct for one instance only and must be asked for explicitly.

## 6. The vectors

`vectors/v<ver>/manifest.json` names the configuration every case runs under and the case list. Each
`vectors/v<ver>/cases/<name>.json` is one verifier's life:

- `fetches`: what each URL answers. The i-th fetch of a URL gets its i-th response, and the last one repeats. A
  missing `body` is an empty one. A status other than 200, including 3xx, is a failed fetch. The script does not
  follow redirects (§2.5).
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

`ver` 6 is the current claim set: claim set 5 plus the `act_kind` value `watch_run`, `run_owner`, and `scope_id` as
an exposed claim, a string when present (§4). Claim set 5
is claim set 4 plus the `act_kind` values `discovery` and `on_behalf`, and `act`; claim set 4 is claim set 3 plus
`sub_id`. A verifier accepts 3, 4, 5 and 6, and passes `vectors/v6`, `vectors/v5`, `vectors/v4` and `vectors/v3`
(§6). A reader that upgrades to 6 without reading `run_owner` loses `sub_id` on runs whose owner Varketa holds an
adopter subject for: read `run_owner` before you rely on `sub_id` for a run. Each library release names the
claim-set versions it accepts and the vector version it passes. See [EVOLUTION.md](EVOLUTION.md).

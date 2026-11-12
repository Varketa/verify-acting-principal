# mcp-on-behalf

Call a Varketa tenant's MCP door as your signed-in customer, from your backend. `@varketa/mcp-on-behalf` runs the
three token hops, binds every token to one DPoP key, caches the result per customer, and gives any MCP client that
takes a `fetch` a credential-bound one.

Not yet released: version `0.0.0`, and its fixture set (`fixtures/v0`) is provisional. Do not depend on it yet.

## Server only

Run it on your backend, never in a browser. Hop 1 signs with your backend's private key, and a browser token is
readable by any script on the page.

## The hops

1. Your backend's own session: an assertion signed by `BackendIdentity`, exchanged at `/login/token-exchange`.
2. The customer's session: the same exchange, with the customer's fresh IdP token as `subject_token` and hop 1's
   session as `actor_token`.
3. The door token: `/oauth/token` with `resource` set to the door's `/mcp` URL.

No hop has a refresh token. A token is held at most five minutes, and re-minted when it runs out.

## Use

```ts
import { BackendIdentity, createOnBehalf } from "@varketa/mcp-on-behalf";
import { clerkSubjectTokens } from "@varketa/mcp-on-behalf/clerk";

const backend = new BackendIdentity({
  issuer: "https://api.example.com",
  subject: "example-backend",
  audience: process.env.VARKETA_ADMISSION_AUDIENCE!,
  privateKeyPem: process.env.BACKEND_SIGNING_KEY!, // or `signer`, for a key in a KMS
});
const onBehalf = createOnBehalf({
  varketaOrigin: "https://app.varketa.ai",
  mcpResource: "https://<tenant>.varketa.ai/mcp",
  backend,
  subjectToken: clerkSubjectTokens({ secretKey: process.env.CLERK_SECRET_KEY!, template: "varketa" }),
});

// Serve the key set at your backend issuer's key URL.
app.get("/.well-known/jwks.json", () => onBehalf.jwks());

// Any MCP client that takes a fetch, e.g. the official SDK's StreamableHTTPClientTransport.
const fetch = await onBehalf.fetchFor({ key: session.sid });

// On sign-out.
onBehalf.forget({ key: session.sid });
```

## What you must supply

- **`CustomerRef.key`**: one key per signed-in session of one customer, from your verified session (for Clerk, the
  session's `sid`). Never from request input, and never reused across customers. It is the ONLY thing that keeps
  customers' cached credentials apart: the kit never reads a token's claims, so two customers under one key share one
  door token for up to five minutes.
- **`subjectToken`**: the signed-in customer's fresh IdP token, minted server-side. The kit calls it once per attempt
  and never caches it.
- **`forget(c)`** when the customer signs out. It also ends any credential a mint in flight returns, and any fetch's
  own fresh credential: none of them is cached or used again.
- **`jwks()`** served at your backend issuer's key URL. Pass `previousKeys` to keep serving a rotated-out key.

## Fresh credentials

`credentialFor(c, { fresh: true })` and `fetchFor(c, { fresh: true })` mint all three hops anew, hop 1 included,
without reading the cache. The result replaces the cached hop 1 and this customer's cached credential, as the newer
one. A fresh fetch keeps the credential it minted. When that credential expires mid-session, the door refuses it
with a 401, or the customer signs out, the fetch mints another fresh one for the next request, with a fresh subject
token; concurrent requests share that one mint. Without `fresh`, the cache is used.

## Retries

No attempt re-presents a subject token: Varketa spends it once, even when it then answers 5xx. Each attempt, the
answer to a DPoP nonce challenge included, fetches a fresh IdP token and signs a fresh assertion. To retry after an
outage, call the kit again; it mints afresh.

## Failures

Each failure is an `OnBehalfError` with its `step`, `status`, `code` and `description`. `classify(e)` says what it
drops:

- an outage (5xx, a timeout, a network error) drops nothing;
- hop 2's `invalid_grant` `actor_token_not_usable` drops hop 1;
- a door 401 drops that customer's credential;
- `invalid_dpop_proof` drops nothing, with reason `kit_defect` and the server's code: the kit built its request wrong;
- any other 4xx at hop 2 or 3 drops that customer's credential.

`reason` is a code. The words your customer reads are yours. Varketa's named refusals come in a later version.

Each call to Varketa times out after `timeoutMs` (default 15 s). Door requests through `fetchFor` carry the
caller's own signal instead.

## The kit never

- sends the IdP token anywhere but hop 2, or caches or logs it;
- sends hop 1's session as a bearer token;
- sends a door token or proof to any URL but `mcpResource` (`fetchFor` refuses before sending);
- falls back to calling as your backend itself, or to the frame exchange;
- exposes or persists its DPoP key.

## Fixtures

`fixtures/v<n>/` holds language-neutral recorded exchanges: each step's expected requests (form fields and DPoP
claims) and the server's answers. `fixtures/v0` is provisional and is replaced by Varketa's own set before a release.

## Releases

Tags `v-on-behalf-X.Y.Z`, published to npm from a signed tag by `.github/workflows/on-behalf-release.yml`.

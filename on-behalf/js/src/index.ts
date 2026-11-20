// @varketa/mcp-on-behalf: call a Varketa tenant's MCP door as your signed-in customer, from your backend.
// Server only. See ../../README.md for what the adopter must supply.
import type { BackendIdentity, Jwk } from "./backend-identity.ts";
import { credentialBoundFetch, type DpopFetch, type NonceBox } from "./dpop-fetch.ts";
import { DEFAULT_TIMEOUT_MS, globalFetch, withTimeout, type HttpFetch } from "./http.ts";
import {
  OnBehalfTokenSource,
  type CustomerRef,
  type McpCredential,
  type SubjectTokenProvider,
} from "./token-source.ts";

export { BackendIdentity, type Es256Signer, type Jwk } from "./backend-identity.ts";
export { classify, type Disposition } from "./disposition.ts";
export type { EcJwk } from "./dpop.ts";
export type { DpopFetch } from "./dpop-fetch.ts";
export { OnBehalfError, type HttpFetch, type OnBehalfReason, type OnBehalfStep } from "./http.ts";
export type { CustomerRef, McpCredential, SubjectTokenProvider } from "./token-source.ts";

export interface OnBehalfOptions {
  /** Serves /login/token-exchange and /oauth/token. */
  varketaOrigin: string;
  /** The tenant door's /mcp URL. No door token or proof is sent anywhere else. */
  mcpResource: string;
  backend: BackendIdentity;
  subjectToken: SubjectTokenProvider;
  /** For the calls to Varketa. Each call carries a timeout signal. */
  fetch?: HttpFetch;
  /** For the door, under fetchFor. The caller's own signal, if any, applies. */
  doorFetch?: DpopFetch;
  /** Ages the cache, in milliseconds. */
  now?: () => number;
  /** Per call to Varketa; default 15 000. Door requests take the caller's own signal. */
  timeoutMs?: number;
  /** Customers' credentials held at most; default 1000. */
  maxCached?: number;
}

export interface OnBehalf {
  /** This customer's door credential: cached, or with `fresh` all three hops minted anew, replacing the cache. */
  credentialFor(c: CustomerRef, o?: { fresh?: boolean }): Promise<McpCredential>;
  /** A fetch for any MCP client that takes one. It adds this customer's door token and a fresh DPoP proof to each
   * request, refuses any URL but mcpResource, answers a door nonce once, and drops the credential on a 401.
   * `fresh`: all three hops minted anew (replacing the cache), and re-minted when it expires or is refused. */
  fetchFor(c: CustomerRef, o?: { fresh?: boolean }): Promise<DpopFetch>;
  /** The adopter's sign-out: drops this customer's credential. */
  forget(c: CustomerRef): void;
  /** After a failed call: drops the `refused` credential if `cause` says it was refused. */
  forget(c: CustomerRef, cause: unknown, refused?: McpCredential): void;
  /** The backend's key set, to serve at its issuer's key URL. */
  jwks(): { keys: Jwk[] };
}

export function createOnBehalf(o: OnBehalfOptions): OnBehalf {
  new URL(o.varketaOrigin);
  new URL(o.mcpResource);
  const maxCached = o.maxCached ?? 1000;
  if (!Number.isInteger(maxCached) || maxCached < 1) throw new Error("maxCached must be a positive integer");
  const source = new OnBehalfTokenSource({
    varketaOrigin: o.varketaOrigin,
    mcpResource: o.mcpResource,
    backend: o.backend,
    subjectToken: o.subjectToken,
    fetch: withTimeout(o.fetch ?? globalFetch, o.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    now: o.now ?? Date.now,
    maxCached,
  });
  const doorNonce: NonceBox = { value: undefined };
  const doorFetch: DpopFetch = o.doorFetch ?? ((url, init) => fetch(url, init));
  function forget(c: CustomerRef, ...why: [] | [cause: unknown, refused?: McpCredential]): void {
    source.forget(c, ...why);
  }
  return {
    credentialFor: (c, opts) => source.credentialFor(c, opts),
    fetchFor: (c, opts) =>
      credentialBoundFetch({
        source,
        customer: c,
        resource: o.mcpResource,
        fresh: opts?.fresh === true,
        nonce: doorNonce,
        fetch: doorFetch,
      }),
    forget,
    jwks: () => o.backend.jwks(),
  };
}

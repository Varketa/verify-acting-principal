import { classify } from "./disposition.ts";
import { OnBehalfError } from "./http.ts";
import type { CustomerRef, McpCredential } from "./token-source.ts";

/** The fetch shape MCP client transports take, the official SDK's StreamableHTTPClientTransport among them. */
export type DpopFetch = (url: string | URL, init?: RequestInit) => Promise<Response>;

/** The parts of the token source a credential-bound fetch uses. */
export interface CredentialSource {
  credentialFor(c: CustomerRef, o?: { fresh?: boolean }): Promise<McpCredential>;
  forget(c: CustomerRef, cause: unknown, refused?: McpCredential): void;
  live(cred: McpCredential): boolean;
}

/** The newest DPoP-Nonce the door sent (RFC 9449 §9), shared by every fetch of one kit. */
export interface NonceBox {
  value: string | undefined;
}

/** The OAuth `error` a WWW-Authenticate challenge names (RFC 6750 §3, RFC 9449 §7.1), if any. */
export function challengeError(res: { headers: { get(name: string): string | null } }): string | null {
  return /\berror="([^"]*)"/.exec(res.headers.get("www-authenticate") ?? "")?.[1] ?? null;
}

// A body that can be sent twice, for the one nonce retry.
const resendable = (body: RequestInit["body"]) => body === undefined || body === null || typeof body === "string";

/** A fetch that sends only to `resource`, adding the customer's door token and a fresh proof to each request. It
 * answers a door nonce once and drops the credential on a 401. `fresh` holds the credential it minted (which
 * also replaces the cached one). When it expires or the door refuses it, the next request mints another fresh one,
 * with a fresh subject token. */
export async function credentialBoundFetch(o: {
  source: CredentialSource;
  customer: CustomerRef;
  resource: string;
  fresh: boolean;
  nonce: NonceBox;
  fetch: DpopFetch;
}): Promise<DpopFetch> {
  const customer = { key: o.customer.key };
  const resource = new URL(o.resource).href;
  // Minted now, so a refusal surfaces from fetchFor itself.
  let own: McpCredential | null = null;
  if (o.fresh) own = await o.source.credentialFor(customer, { fresh: true });
  else await o.source.credentialFor(customer);
  const credential = async () => {
    if (!o.fresh) return o.source.credentialFor(customer);
    if (own === null || !o.source.live(own)) own = await o.source.credentialFor(customer, { fresh: true });
    return own;
  };

  return async (url, init = {}) => {
    const href = new URL(url).href;
    if (href !== resource) throw new Error("the on-behalf fetch sends to the configured mcpResource only");
    const cred = await credential();
    const method = (init.method ?? "GET").toUpperCase();
    const send = () => {
      const headers = new Headers(init.headers);
      headers.set("authorization", `DPoP ${cred.accessToken}`);
      const nonce = o.nonce.value;
      headers.set("dpop", cred.proof(method, href, nonce !== undefined ? { nonce } : {}));
      return o.fetch(href, { ...init, method, headers });
    };
    let res = await send();
    o.nonce.value = res.headers.get("dpop-nonce") ?? o.nonce.value;
    if (
      res.status === 401 &&
      res.headers.get("dpop-nonce") !== null &&
      challengeError(res) === "use_dpop_nonce" &&
      resendable(init.body)
    ) {
      await res.body?.cancel();
      res = await send();
      o.nonce.value = res.headers.get("dpop-nonce") ?? o.nonce.value;
    }
    if (res.status === 401) {
      const refusal = new OnBehalfError("door", 401, challengeError(res), { what: "the MCP door" });
      o.source.forget(customer, refusal, cred);
      if (own === cred && classify(refusal).dropCustomer) own = null;
    }
    return res;
  };
}

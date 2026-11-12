import type { BackendIdentity } from "./backend-identity.ts";
import { classify } from "./disposition.ts";
import { DpopKey } from "./dpop.ts";
import { OnBehalfError, parseJson, type HttpFetch, type OnBehalfStep } from "./http.ts";

/** ONE signed-in session of ONE customer. `key` is the only thing that keeps customers' cached credentials apart:
 * take it from the adopter's verified session, never from request input, and never reuse it across customers. */
export interface CustomerRef {
  key: string;
}

/** The customer's FRESH IdP token, minted server-side. Called once per attempt; the kit never caches it. */
export type SubjectTokenProvider = (c: CustomerRef) => Promise<string>;

/** A door token and its proof. The DPoP key stays inside the kit. */
export interface McpCredential {
  readonly accessToken: string;
  /** A DPoP proof for one request to the door, with `ath` bound to `accessToken`. */
  proof(method: string, url: string, o?: { nonce?: string }): string;
}

const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT = "urn:ietf:params:oauth:token-type:jwt";
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
// A cached token is used only while it has this much life left.
const MARGIN_MS = 30_000;
// No token is held longer than this, whatever lifetime an answer claims.
const MAX_TTL_MS = 5 * 60_000;

interface Timed {
  token: string;
  expiresAt: number;
}

type Form = () => Promise<Record<string, string>>;

/**
 * The three hops:
 *  1. the backend's own session: its BackendIdentity assertion exchanged at `/login/token-exchange`;
 *  2. the customer's session: the same exchange, the customer's fresh IdP token as `subject_token` and the
 *     backend's session as `actor_token`;
 *  3. the door's token: `/oauth/token` with `resource` = the door's `/mcp`.
 * Every token is DPoP-bound to one in-memory key.
 */
export class OnBehalfTokenSource {
  readonly #origin: string;
  readonly #resource: string;
  readonly #backend: BackendIdentity;
  readonly #subject: SubjectTokenProvider;
  readonly #fetch: HttpFetch;
  readonly #now: () => number;
  readonly #maxCached: number;
  readonly #key = DpopKey.generate();
  #actor: Timed | null = null;
  #actorInFlight: Promise<Timed> | null = null;
  // The newest DPoP-Nonce the authorization server sent, on every later proof (RFC 9449 §8).
  #nonce: string | undefined;
  // In insertion order: the first key is the earliest inserted.
  readonly #customers = new Map<string, Timed>();
  readonly #inFlight = new Map<string, Promise<Timed>>();
  // Each credential handed out, with its lifetime, so a holder can ask whether it is still live.
  readonly #issued = new WeakMap<McpCredential, Timed>();

  constructor(o: {
    varketaOrigin: string;
    mcpResource: string;
    backend: BackendIdentity;
    subjectToken: SubjectTokenProvider;
    fetch: HttpFetch;
    now: () => number;
    maxCached: number;
  }) {
    this.#origin = o.varketaOrigin.replace(/\/+$/, "");
    this.#resource = o.mcpResource;
    this.#backend = o.backend;
    this.#subject = o.subjectToken;
    this.#fetch = o.fetch;
    this.#now = o.now;
    this.#maxCached = o.maxCached;
  }

  #live(t: Timed | null | undefined): t is Timed {
    return t !== null && t !== undefined && t.expiresAt - MARGIN_MS > this.#now();
  }

  /** One grant. `form` runs afresh for each send, so no attempt re-presents a subject token: the exchange spends
   * its `jti` once, and a second send of it can only be refused. */
  async #grant(path: string, form: Form, what: string, step: OnBehalfStep): Promise<Timed> {
    const url = `${this.#origin}${path}`;
    const send = async () => {
      const body = new URLSearchParams(await form()).toString();
      const nonce = this.#nonce;
      const res = await this.#fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: this.#key.proof("POST", url, nonce !== undefined ? { nonce } : {}),
        },
        body,
      });
      this.#nonce = res.headers.get("dpop-nonce") ?? this.#nonce;
      return {
        res,
        body: parseJson(await res.text()) as {
          access_token?: unknown;
          token_type?: unknown;
          expires_in?: unknown;
          error?: unknown;
          error_description?: unknown;
        } | null,
      };
    };
    let { res, body } = await send();
    // RFC 9449 §8: a server that wants a (new) nonce refuses with use_dpop_nonce; answer it once.
    if (res.status === 400 && body?.error === "use_dpop_nonce" && res.headers.get("dpop-nonce") !== null) {
      ({ res, body } = await send());
    }
    // Every token is DPoP-bound (RFC 9449 §5): one issued as anything else is refused, not cached.
    if (
      res.status !== 200 ||
      typeof body?.access_token !== "string" ||
      typeof body.expires_in !== "number" ||
      typeof body.token_type !== "string" ||
      body.token_type.toLowerCase() !== "dpop"
    ) {
      throw new OnBehalfError(step, res.status, typeof body?.error === "string" ? body.error : null, {
        what,
        description: typeof body?.error_description === "string" ? body.error_description : null,
      });
    }
    return { token: body.access_token, expiresAt: this.#now() + Math.min(body.expires_in * 1000, MAX_TTL_MS) };
  }

  /** Hop 1, minted anew. It replaces the cached one, as the newer session. */
  #mintActor(): Promise<Timed> {
    return this.#grant(
      "/login/token-exchange",
      // Varketa reads the assertion's times against its own clock, so they come from the wall clock, as the
      // proofs' do; `now` only ages the cache.
      async () => ({
        grant_type: TOKEN_EXCHANGE,
        subject_token: await this.#backend.assertion(Math.floor(Date.now() / 1000)),
        subject_token_type: JWT,
      }),
      "Varketa's exchange (backend)",
      "backend",
    ).then((t) => {
      this.#actor = t;
      return t;
    });
  }

  /** The backend's own session, shared by every customer's exchange while it lives. `fresh` mints it anew: a
   * customer session lives no longer than its actor, so a fresh credential never starts from a cached hop 1. */
  async #actorSession(fresh: boolean): Promise<Timed> {
    if (fresh) return this.#mintActor();
    if (this.#live(this.#actor)) return this.#actor;
    this.#actorInFlight ??= this.#mintActor().finally(() => {
      this.#actorInFlight = null;
    });
    return this.#actorInFlight;
  }

  async #subjectToken(c: CustomerRef): Promise<string> {
    try {
      return await this.#subject({ key: c.key });
    } catch (e) {
      if (e instanceof OnBehalfError) throw e;
      throw new OnBehalfError("subject", 0, null, { what: "the subject token provider", cause: e });
    }
  }

  async #mint(c: CustomerRef, fresh = false): Promise<Timed> {
    const actor = await this.#actorSession(fresh);
    let customer: Timed;
    try {
      customer = await this.#grant(
        "/login/token-exchange",
        async () => ({
          grant_type: TOKEN_EXCHANGE,
          subject_token: await this.#subjectToken(c),
          subject_token_type: JWT,
          actor_token: actor.token,
          actor_token_type: ACCESS_TOKEN,
        }),
        "Varketa's exchange (customer)",
        "customer",
      );
    } catch (e) {
      // Only the refusal that names the backend's session drops it, and never a newer one.
      if (classify(e).dropActor && this.#actor === actor) this.#actor = null;
      throw e;
    }
    const door = await this.#grant(
      "/oauth/token",
      async () => ({
        grant_type: TOKEN_EXCHANGE,
        subject_token: customer.token,
        subject_token_type: ACCESS_TOKEN,
        resource: this.#resource,
      }),
      "Varketa's token endpoint",
      "door_token",
    );
    return { token: door.token, expiresAt: Math.min(door.expiresAt, customer.expiresAt) };
  }

  /** Inserts at the end. Expired entries go first, then the earliest inserted, until there is room. */
  #remember(key: string, t: Timed): void {
    this.#customers.delete(key);
    for (const [k, v] of this.#customers) if (!this.#live(v)) this.#customers.delete(k);
    while (this.#customers.size >= this.#maxCached) {
      const first = this.#customers.keys().next().value;
      if (first === undefined) break;
      this.#customers.delete(first);
    }
    this.#customers.set(key, t);
  }

  #credential(t: Timed): McpCredential {
    const key = this.#key;
    const resource = new URL(this.#resource).href;
    const accessToken = t.token;
    const cred: McpCredential = Object.freeze({
      accessToken,
      proof(method: string, url: string, o: { nonce?: string } = {}): string {
        if (new URL(url).href !== resource) throw new Error("a door proof is made for the configured mcpResource only");
        const nonce = o.nonce !== undefined ? { nonce: o.nonce } : {};
        return key.proof(method.toUpperCase(), url, { accessToken, ...nonce });
      },
    });
    this.#issued.set(cred, t);
    return cred;
  }

  /** Whether `cred` still has more than the margin of its life left. */
  live(cred: McpCredential): boolean {
    return this.#live(this.#issued.get(cred));
  }

  async credentialFor(c: CustomerRef, o: { fresh?: boolean } = {}): Promise<McpCredential> {
    const key = c.key;
    if (typeof key !== "string" || key === "") throw new Error("CustomerRef.key must be a non-empty string");
    // A fresh credential mints all three hops without reading the cache, then replaces this customer's cached
    // entry as the newer credential. A mint already in flight for the key is then left uncached.
    if (o.fresh === true) {
      const t = await this.#mint({ key }, true);
      this.#inFlight.delete(key);
      this.#remember(key, t);
      return this.#credential(t);
    }
    const cached = this.#customers.get(key);
    if (this.#live(cached)) return this.#credential(cached);
    let pending = this.#inFlight.get(key);
    if (pending === undefined) {
      const p: Promise<Timed> = this.#mint({ key }).then(
        (t) => {
          // A forget() while this was in flight leaves it uncached.
          if (this.#inFlight.get(key) === p) {
            this.#inFlight.delete(key);
            this.#remember(key, t);
          }
          return t;
        },
        (e: unknown) => {
          if (this.#inFlight.get(key) === p) this.#inFlight.delete(key);
          throw e;
        },
      );
      this.#inFlight.set(key, p);
      pending = p;
    }
    return this.#credential(await pending);
  }

  /** With no cause, drops this customer's credential (sign-out). With a cause, drops it only when the cause says
   * the credential was refused, and only the `refused` one, never a newer one cached since. */
  forget(c: CustomerRef, ...why: [] | [cause: unknown, refused?: McpCredential]): void {
    if (why.length > 0) {
      const [cause, refused] = why;
      if (!classify(cause).dropCustomer) return;
      if (refused !== undefined && this.#customers.get(c.key)?.token !== refused.accessToken) return;
    } else {
      this.#inFlight.delete(c.key);
    }
    this.#customers.delete(c.key);
  }
}

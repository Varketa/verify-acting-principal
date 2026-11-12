// Stand-ins for the customer's IdP, Varketa's authorization server and the tenant's MCP door. Each checks what the
// real one would: a valid DPoP proof on every request, one key binding every token, the backend's assertion under
// the key set the kit serves, each subject token presented once, and the door token with the key it is bound to.
// With a script (a fixture case's exchanges) each request must match the next exchange and gets its recorded answer.
import { createHash, createPublicKey, verify, type JsonWebKey } from "node:crypto";
import type { DpopFetch, EcJwk, HttpFetch, SubjectTokenProvider } from "../../src/index.ts";
import { jwkThumbprint } from "../../src/dpop.ts";

export const VARKETA = "https://varketa.example";
export const MCP = "https://tenant.varketa.example/mcp";
export const CLERK_API = "https://clerk.example";
export const BACKEND = { issuer: "https://backend.adopter.example", subject: "backend", audience: "varketa-aud" };

export type Step = "subject" | "backend" | "customer" | "door_token" | "door";
export interface Answer {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
}
export interface Expected {
  method: string;
  url: string;
  /** Exactly these form fields. "$assertion": a fresh backend assertion; "$subject": a fresh subject token. */
  form?: Record<string, string>;
  /** These headers, among others. */
  headers?: Record<string, string>;
  /** The proof's nonce, if any, and whether it carries `ath`. */
  dpop?: { nonce?: string | null; ath?: boolean };
}
export interface Exchange {
  request: Expected;
  response: Answer;
}
export interface Recorded {
  step: Step;
  url: string;
  method: string;
  headers: Record<string, string>;
  form: Record<string, string> | null;
  body: string | null;
  proof: { header: Record<string, unknown>; payload: Record<string, unknown> } | null;
}

const decode = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString()) as Record<string, unknown>;

export function verifyEs256(jws: string, jwk: EcJwk) {
  const [h, p, s] = jws.split(".");
  if (!h || !p || !s) throw new Error("not a compact JWS");
  const ok = verify(
    "sha256",
    Buffer.from(`${h}.${p}`),
    { key: createPublicKey({ key: jwk as unknown as JsonWebKey, format: "jwk" }), dsaEncoding: "ieee-p1363" },
    Buffer.from(s, "base64url"),
  );
  if (!ok) throw new Error("the signature does not verify");
  return { header: decode(h), payload: decode(p) };
}

const ath = (token: string) => createHash("sha256").update(token).digest("base64url");

export class FakeVarketa {
  readonly log: string[] = [];
  readonly requests: Recorded[] = [];
  readonly problems: string[] = [];
  readonly jkts = new Set<string>();
  /** Every subject token the IdP issued, and every backend assertion `jti` the exchange was sent. */
  readonly subjects: string[] = [];
  readonly jtis: string[] = [];
  ttl = { backend: 300, customer: 300, door: 300 };
  doorTokenType = "DPoP";
  readonly #jwks: () => { keys: (EcJwk & { kid: string })[] };
  readonly #once = new Map<Step, Answer[]>();
  #script: Exchange[] | null = null;
  #n = 0;
  readonly #presented = new Set<string>();
  readonly #actors = new Set<string>();
  readonly #customers = new Set<string>();
  readonly #doors = new Map<string, string>(); // door token -> jkt

  constructor(jwks: () => { keys: (EcJwk & { kid: string })[] }) {
    this.#jwks = jwks;
  }

  /** The next request at `step` gets `answer` (queued, each used once). */
  once(step: Step, answer: Answer): void {
    this.#once.set(step, [...(this.#once.get(step) ?? []), answer]);
  }

  /** From now on every request must match the next of `exchanges`. */
  script(exchanges: Exchange[]): void {
    this.#script = [...exchanges];
  }

  /** Throws if any check failed or a scripted exchange was never asked for. */
  done(): void {
    if (this.#script !== null && this.#script.length > 0) {
      this.problems.push(`${this.#script.length} scripted exchange(s) never sent: ${this.#script[0]?.request.url}`);
    }
    if (this.problems.length > 0) throw new Error(this.problems.join("\n"));
  }

  #fail(message: string): never {
    this.problems.push(message);
    throw new Error(`fake: ${message}`);
  }

  #check(ok: unknown, message: string): void {
    if (!ok) this.#fail(message);
  }

  /** The IdP: a fresh token per call. */
  readonly subjectToken: SubjectTokenProvider = async (c) => {
    this.log.push(`subject:${c.key}`);
    const answer = this.#once.get("subject")?.shift();
    if (answer !== undefined) throw new Error(`the IdP answered ${answer.status}`);
    const t = `idp-${c.key}-${++this.#n}`;
    this.subjects.push(t);
    return t;
  };

  #proof(rec: Recorded, accessToken?: string) {
    const jws = rec.headers.dpop;
    if (jws === undefined) this.#fail(`no DPoP proof on ${rec.url}`);
    const header = decode(jws.split(".")[0] ?? "");
    this.#check(header.typ === "dpop+jwt", "the proof's typ is dpop+jwt");
    this.#check(!("d" in (header.jwk as object)), "the proof's jwk holds no private member");
    const proof = verifyEs256(jws, header.jwk as EcJwk);
    const u = new URL(rec.url);
    this.#check(proof.payload.htm === rec.method, `htm ${String(proof.payload.htm)} is ${rec.method}`);
    this.#check(proof.payload.htu === `${u.origin}${u.pathname}`, `htu ${String(proof.payload.htu)}`);
    this.#check(Math.abs(Number(proof.payload.iat) - Date.now() / 1000) < 30, "iat is now");
    this.#check(typeof proof.payload.jti === "string", "the proof has a jti");
    if (accessToken !== undefined) this.#check(proof.payload.ath === ath(accessToken), "ath binds the token");
    else this.#check(proof.payload.ath === undefined, "no ath at the authorization server");
    this.jkts.add(jwkThumbprint(header.jwk as EcJwk));
    rec.proof = proof;
    return { jkt: jwkThumbprint(header.jwk as EcJwk), nonce: proof.payload.nonce };
  }

  #assertion(token: string) {
    const kid = decode(token.split(".")[0] ?? "").kid;
    const key = this.#jwks().keys.find((k) => k.kid === kid);
    if (key === undefined) this.#fail("the assertion's kid is not in the backend's key set");
    const { payload } = verifyEs256(token, key);
    this.#check(payload.iss === BACKEND.issuer && payload.sub === BACKEND.subject, "the assertion's iss and sub");
    this.#check(payload.aud === BACKEND.audience, "the assertion's aud");
    this.#check(Number(payload.exp) - Number(payload.iat) === 60, "a one-minute assertion");
    this.#check(!this.jtis.includes(String(payload.jti)), "a fresh assertion jti");
    this.jtis.push(String(payload.jti));
  }

  #subject(token: string) {
    this.#check(this.subjects.includes(token), "the subject token is one the IdP issued");
    this.#check(!this.#presented.has(token), `subject token ${token} presented twice`);
    this.#presented.add(token);
  }

  #match(rec: Recorded): Answer {
    const next = this.#script?.shift();
    if (next === undefined) this.#fail(`unexpected ${rec.method} ${rec.url}`);
    const want = next.request;
    this.#check(rec.method === want.method && rec.url === want.url, `${rec.method} ${rec.url}; want ${want.url}`);
    if (want.form !== undefined) {
      const got = rec.form ?? {};
      this.#check(
        JSON.stringify(Object.keys(got).sort()) === JSON.stringify(Object.keys(want.form).sort()),
        `form fields ${Object.keys(got).sort().join(",")}`,
      );
      for (const [k, v] of Object.entries(want.form)) {
        if (v === "$assertion") this.#assertion(got[k] ?? "");
        else if (v === "$subject") this.#subject(got[k] ?? "");
        else this.#check(got[k] === v, `form ${k} is ${got[k]}; want ${v}`);
      }
    }
    for (const [k, v] of Object.entries(want.headers ?? {})) this.#check(rec.headers[k] === v, `header ${k}`);
    if (want.dpop?.nonce !== undefined) {
      this.#check((rec.proof?.payload.nonce ?? null) === want.dpop.nonce, `proof nonce ${want.dpop.nonce}`);
    }
    if (want.dpop?.ath !== undefined) this.#check((rec.proof?.payload.ath !== undefined) === want.dpop.ath, "ath");
    return next.response;
  }

  #record(step: Step, url: string, method: string, headers: Record<string, string>, body: string | null) {
    const form = step === "door" ? null : Object.fromEntries(new URLSearchParams(body ?? ""));
    const rec: Recorded = { step, url, method, headers, form, body, proof: null };
    this.requests.push(rec);
    return rec;
  }

  /** Varketa's authorization server (and the Clerk API, for the adapter). */
  readonly fetch: HttpFetch = async (url, init) => {
    const reply = (a: Answer) => {
      const h = Object.fromEntries(Object.entries(a.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
      return {
        status: a.status,
        headers: { get: (k: string) => h[k.toLowerCase()] ?? null },
        text: async () => (a.body === undefined ? "" : typeof a.body === "string" ? a.body : JSON.stringify(a.body)),
      };
    };
    if (url.startsWith(`${CLERK_API}/v1/sessions/`)) {
      const m = /\/v1\/sessions\/([^/]+)\/tokens\/varketa$/.exec(url);
      this.#check(m !== null && init.headers.authorization === "Bearer sk_test_fake", "a Clerk template request");
      this.log.push(`clerk:${m?.[1]}`);
      const t = `clerk-${m?.[1]}-${++this.#n}`;
      this.subjects.push(t);
      return reply({ status: 200, body: { object: "token", jwt: t } });
    }
    this.#check(init.signal instanceof AbortSignal, "every call to Varketa carries a timeout signal");
    this.#check(init.headers.authorization === undefined, "no authorization header at the authorization server");
    let step: Step;
    if (url === `${VARKETA}/login/token-exchange`) {
      step = new URLSearchParams(init.body ?? "").has("actor_token") ? "customer" : "backend";
    } else if (url === `${VARKETA}/oauth/token`) {
      step = "door_token";
    } else {
      this.#fail(`unexpected call ${url}`);
    }
    const rec = this.#record(step, url, init.method, { ...init.headers }, init.body ?? null);
    const { jkt } = this.#proof(rec);
    this.log.push(`as:${step}`);
    if (this.#script !== null) return reply(this.#match(rec));

    const f = rec.form ?? {};
    this.#check(f.grant_type === "urn:ietf:params:oauth:grant-type:token-exchange", "the token-exchange grant");
    if (step === "backend") {
      this.#check(f.subject_token_type === "urn:ietf:params:oauth:token-type:jwt", "a JWT subject");
      this.#assertion(f.subject_token ?? "");
    } else if (step === "customer") {
      this.#subject(f.subject_token ?? "");
      this.#check(this.#actors.has(f.actor_token ?? ""), "the actor token is a backend session Varketa minted");
      this.#check(f.actor_token_type === "urn:ietf:params:oauth:token-type:access_token", "actor_token_type");
    } else {
      this.#check(this.#customers.has(f.subject_token ?? ""), "the subject is a customer session Varketa minted");
      this.#check(f.resource === MCP, "resource is the door");
    }
    const once = this.#once.get(step)?.shift();
    if (once !== undefined) {
      this.log.push(`refused:${step}`);
      return reply(once);
    }
    const token = `${step}-${++this.#n}`;
    if (step === "backend") this.#actors.add(token);
    if (step === "customer") this.#customers.add(token);
    if (step === "door_token") this.#doors.set(token, jkt);
    const ttl = step === "backend" ? this.ttl.backend : step === "customer" ? this.ttl.customer : this.ttl.door;
    const type = step === "door_token" ? this.doorTokenType : "DPoP";
    return reply({ status: 200, body: { access_token: token, token_type: type, expires_in: ttl } });
  };

  /** The tenant's MCP door. */
  readonly doorFetch: DpopFetch = async (url, init = {}) => {
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    const href = new URL(url).href;
    const method = init.method ?? "GET";
    const rec = this.#record("door", href, method, headers, typeof init.body === "string" ? init.body : null);
    this.#check(href === MCP, `the door got a request for ${href}`);
    const token = /^DPoP (.+)$/.exec(headers.authorization ?? "")?.[1];
    if (token === undefined) this.#fail("the door's request carries no DPoP token");
    const { jkt } = this.#proof(rec, token);
    this.log.push(`door:${method}`);
    const respond = (a: Answer) => {
      const body = a.body === undefined ? null : typeof a.body === "string" ? a.body : JSON.stringify(a.body);
      return new Response(a.status === 204 ? null : body, { status: a.status, headers: a.headers });
    };
    if (this.#script !== null) return respond(this.#match(rec));
    this.#check(this.#doors.get(token) === jkt, "the door token is used with the key it is bound to");
    const once = this.#once.get("door")?.shift();
    if (once !== undefined) {
      this.log.push("refused:door");
      return respond(once);
    }
    if (method === "DELETE") return respond({ status: 204 });
    if (method === "GET") return respond({ status: 200, headers: { "content-type": "text/event-stream" }, body: "" });
    return respond({ status: 200, headers: { "content-type": "application/json" }, body: { jsonrpc: "2.0" } });
  };
}

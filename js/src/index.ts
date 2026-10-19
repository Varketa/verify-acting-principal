// @varketa/verify-acting-principal: verify the Varketa-Acting-Principal header, claim set versions 3 and 4.
// The normative half is ../../SPEC.md and ../../vectors/v4; this file follows the spec's order.
import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";

export const HEADER = "Varketa-Acting-Principal";
export const TYP = "varketa-acting-principal+jwt";
export const SUPPORTED_VERSIONS: readonly number[] = [3, 4];
const ALGORITHMS: Record<string, { hash: string | null; kty: string; crv: string }> = {
  ES256: { hash: "sha256", kty: "EC", crv: "P-256" },
  ES384: { hash: "sha384", kty: "EC", crv: "P-384" },
  EdDSA: { hash: null, kty: "OKP", crv: "Ed25519" },
};
const SKEW = 60;
const MAX_LIFETIME = 120;
const MAX_CACHE = 300;
const REFETCH_INTERVAL = 60;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_DOCUMENT_BYTES = 64 * 1024;
export const METADATA_PATH = "/.well-known/varketa-acting-principal";

/** One code per refusal, in the spec's order. */
export type Code =
  | "malformed" | "typ" | "alg" | "jwks_unavailable" | "kid" | "signature" | "iss" | "ver" | "adopter" | "aud"
  | "not_yet_valid" | "expired" | "lifetime" | "htm" | "htu" | "bdy" | "replay";

export class VerificationError extends Error {
  readonly code: Code;
  constructor(code: Code, message?: string) {
    super(message ?? code);
    this.name = "VerificationError";
    this.code = code;
  }
}

/** A fetched document. `fetchDocument` must not follow a redirect. */
export interface FetchedDocument { status: number; cacheControl: string | null; body: string }
export type FetchDocument = (url: string) => Promise<FetchedDocument>;

/**
 * The replay record. `setIfAbsent` inserts `key` with a time to live and reports whether THIS call inserted it, in one
 * atomic step: of two concurrent calls with one key, exactly one returns true. Never implement it as a read followed
 * by a write.
 */
export interface ReplayStore { setIfAbsent(key: string, ttlSeconds: number, now: number): Promise<boolean> }

/** An in-process replay store. It is correct only for an API served by ONE instance, so it must be asked for. */
export class InMemoryReplayStore implements ReplayStore {
  readonly #seen = new Map<string, number>();
  #inserts = 0;
  constructor(options: { singleInstance: true }) {
    if (options?.singleInstance !== true) {
      throw new Error("InMemoryReplayStore is for a single instance only: pass { singleInstance: true }, or supply a shared store");
    }
  }
  async setIfAbsent(key: string, ttlSeconds: number, now: number): Promise<boolean> {
    const until = this.#seen.get(key);
    if (until !== undefined && now < until) return false;
    this.#seen.set(key, now + ttlSeconds);
    // Expired records are swept every 1024 inserts, so the store holds about one assertion lifetime of jtis.
    if (++this.#inserts % 1024 === 0) {
      for (const [k, u] of this.#seen) if (u <= now) this.#seen.delete(k);
    }
    return true;
  }
}

export interface Options {
  /** Varketa's issuer, e.g. "https://api.varketa.ai". Required. */
  issuer: string;
  /** This API's adopter id, shown on Varketa's Tool sources page. Required. */
  adopter: string;
  /** This API's own origin, the `aud` Varketa signs. Required. */
  audience: string;
  /** Required: no silent default (see InMemoryReplayStore). */
  replayStore: ReplayStore;
  /** Seconds since the epoch. Defaults to the system clock. */
  clock?: () => number;
  fetchDocument?: FetchDocument;
  /** Maps the URL as received to the URL the caller sent, after this API's own proxies. Defaults to identity. */
  requestUrl?: (url: string) => string;
}

/** The caller as the adopter's own identity provider names it: RFC 9493's iss_sub subject identifier. */
export interface SubjectId { format: "iss_sub"; iss: string; sub: string }

export interface Identity {
  sub?: string; grant?: string; tenant: string; adopter: string; persona?: string; scopes?: string[];
  act_kind?: string; presence?: string; run_id?: string; approved_by?: unknown; probe?: true;
  sub_id?: SubjectId;
}

export interface Request { method: string; url: string; body: Uint8Array | string; assertion: string | null | undefined }

// A bounded fetch: no redirect, 10 s, and at most 64 KiB, so a stalled or oversized issuer answer fails closed.
const defaultFetch: FetchDocument = async (url) => {
  const r = await fetch(url, { redirect: "error", headers: { accept: "application/json" }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of r.body ?? []) {
    size += chunk.length;
    if (size > MAX_DOCUMENT_BYTES) throw new Error(`${url}: document over ${MAX_DOCUMENT_BYTES} bytes`);
    chunks.push(chunk);
  }
  return { status: r.status, cacheControl: r.headers.get("cache-control"),
    body: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)) };
};

function maxAge(cacheControl: string | null): number {
  const m = /(?:^|,)\s*max-age=(\d+)/i.exec(cacheControl ?? "");
  return m ? Math.min(Number(m[1]), MAX_CACHE) : 0;
}

function b64url(s: string): Buffer {
  if (/[^A-Za-z0-9_-]/.test(s) || s.length % 4 === 1) throw new VerificationError("malformed");
  return Buffer.from(s, "base64url");
}

function json(b: Buffer): Record<string, unknown> {
  try {
    const v = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b));
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new VerificationError("malformed");
  }
}

export class Verifier {
  readonly #o: Required<Omit<Options, "fetchDocument" | "clock" | "requestUrl">>;
  readonly #fetch: FetchDocument;
  readonly #clock: () => number;
  readonly #requestUrl: (url: string) => string;
  #jwksUri = "";
  #mdFetchedAt = 0;
  #mdMaxAge = 0;
  #keys: Map<string, Record<string, unknown>> | null = null;
  #fetchedAt = 0;
  #maxAge = 0;
  #lastRefetch: number | null = null;
  #loading: Promise<boolean> | null = null;

  constructor(options: Options) {
    for (const k of ["issuer", "adopter", "audience"] as const) {
      if (typeof options?.[k] !== "string" || options[k].trim() === "") throw new Error(`verify-acting-principal: ${k} is required`);
    }
    if (!options.replayStore) throw new Error("verify-acting-principal: replayStore is required (no silent default)");
    for (const k of ["issuer", "audience"] as const) {
      let origin = "";
      try { origin = new URL(options[k]).origin; } catch { /* refused below */ }
      if (!options[k].startsWith("https://") || origin !== options[k]) {
        throw new Error(`verify-acting-principal: ${k} must be an https:// origin`);
      }
    }
    this.#o = { issuer: options.issuer, adopter: options.adopter, audience: options.audience, replayStore: options.replayStore };
    this.#fetch = options.fetchDocument ?? defaultFetch;
    this.#clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    this.#requestUrl = options.requestUrl ?? ((u) => u);
  }

  async #load(now: number): Promise<boolean> {
    // Concurrent requests share one discovery transaction, so an older key fetch cannot overwrite a newer one.
    if (this.#loading) return this.#loading;
    this.#loading = this.#reload(now);
    try { return await this.#loading; } finally { this.#loading = null; }
  }

  async #reload(now: number): Promise<boolean> {
    if (this.#jwksUri === "" || now - this.#mdFetchedAt >= this.#mdMaxAge) {
      const md = await this.#get(this.#o.issuer + METADATA_PATH);
      if (!md) return false;
      let doc: Record<string, unknown>;
      try { doc = json(Buffer.from(md.body)); } catch { return false; }
      if (doc.issuer !== this.#o.issuer || typeof doc.jwks_uri !== "string" || !doc.jwks_uri.startsWith("https://")) return false;
      this.#jwksUri = doc.jwks_uri;
      this.#mdFetchedAt = now;
      this.#mdMaxAge = maxAge(md.cacheControl);
    }
    const r = await this.#get(this.#jwksUri);
    let keys: unknown;
    try { keys = r && json(Buffer.from(r.body)).keys; } catch { keys = undefined; }
    if (!r || !Array.isArray(keys)) { this.#keys = null; return false; }
    this.#keys = new Map(keys.filter((k) => k && typeof k.kid === "string").map((k) => [k.kid as string, k]));
    this.#fetchedAt = now;
    this.#maxAge = maxAge(r.cacheControl);
    return true;
  }

  async #get(url: string): Promise<FetchedDocument | null> {
    try {
      const r = await this.#fetch(url);
      return r.status === 200 ? r : null;
    } catch {
      return null;
    }
  }

  /** Verifies one request's assertion and returns the identity to authorize against, or throws VerificationError. */
  async verify(req: Request): Promise<Identity> {
    const now = this.#clock();
    const parts = (req.assertion ?? "").split(".");
    if (parts.length !== 3) throw new VerificationError("malformed");
    const header = json(b64url(parts[0]));
    if (header.typ !== TYP) throw new VerificationError("typ");
    const alg = typeof header.alg === "string" ? ALGORITHMS[header.alg] : undefined;
    if (!alg || !Object.hasOwn(ALGORITHMS, header.alg as string)) throw new VerificationError("alg");
    if (this.#keys === null || now - this.#fetchedAt >= this.#maxAge || now - this.#mdFetchedAt >= this.#mdMaxAge) {
      if (!(await this.#load(now))) throw new VerificationError("jwks_unavailable");
    }
    const kid = typeof header.kid === "string" ? header.kid : "";
    let jwk = this.#keys?.get(kid);
    if (!jwk && (this.#lastRefetch === null || now - this.#lastRefetch >= REFETCH_INTERVAL)) {
      this.#lastRefetch = now;
      if (await this.#load(now)) jwk = this.#keys?.get(kid);
    }
    // A network wait may itself consume the documents' positive cache lifetime.
    const keyAt = this.#clock();
    if ((this.#mdMaxAge > 0 && keyAt - this.#mdFetchedAt >= this.#mdMaxAge) ||
        (this.#maxAge > 0 && keyAt - this.#fetchedAt >= this.#maxAge)) throw new VerificationError("jwks_unavailable");
    if (!jwk) throw new VerificationError("kid");
    let key: KeyObject;
    try {
      if (jwk.kty !== alg.kty || jwk.crv !== alg.crv || (jwk.alg !== undefined && jwk.alg !== header.alg)) throw new Error();
      key = createPublicKey({ key: jwk as never, format: "jwk" });
    } catch {
      throw new VerificationError("signature");
    }
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    const sig = b64url(parts[2]);
    const ok = alg.hash === null
      ? verifySignature(null, signed, key, sig)
      : verifySignature(alg.hash, signed, { key, dsaEncoding: "ieee-p1363" }, sig);
    if (!ok) throw new VerificationError("signature");
    const c = json(b64url(parts[1]));
    // The clock again, after any key-set wait: the time checks and the replay record's lifetime use it.
    const at = this.#clock();
    const str = (k: string) => (typeof c[k] === "string" ? (c[k] as string) : undefined);
    // Integers only: a fractional ver, iat or exp is not truncated to a known value; it is absent.
    const num = (k: string) => (Number.isSafeInteger(c[k]) ? (c[k] as number) : undefined);
    const iat = num("iat"), exp = num("exp");
    const body = typeof req.body === "string" ? Buffer.from(req.body, "utf8") : Buffer.from(req.body);
    if (str("iss") !== this.#o.issuer) throw new VerificationError("iss");
    if (!SUPPORTED_VERSIONS.includes(num("ver") ?? NaN)) throw new VerificationError("ver");
    if (str("adopter") !== this.#o.adopter) throw new VerificationError("adopter");
    if (str("aud") !== this.#o.audience) throw new VerificationError("aud");
    if (iat === undefined || iat > at + SKEW) throw new VerificationError("not_yet_valid");
    if (exp === undefined || at > exp + SKEW) throw new VerificationError("expired");
    if (exp - iat > MAX_LIFETIME) throw new VerificationError("lifetime");
    if (str("htm") !== req.method) throw new VerificationError("htm");
    if (str("htu") !== this.#requestUrl(req.url)) throw new VerificationError("htu");
    if (str("bdy") !== createHash("sha256").update(body).digest("base64url")) throw new VerificationError("bdy");
    const jti = str("jti"), tenant = str("tenant");
    // The claims Varketa never omits and an API authorizes on: the jti, the tenant, and the subject or grant.
    if (!jti || !tenant || (!str("sub") && !str("grant"))) throw new VerificationError("malformed");
    // A PRESENT sub_id is exactly RFC 9493's iss_sub, its iss and sub non-empty strings, or the assertion is malformed:
    // a verifier never exposes half a subject.
    let subId: SubjectId | undefined;
    if (Object.hasOwn(c, "sub_id")) {
      const v = c.sub_id as Record<string, unknown> | null;
      if (typeof v !== "object" || v === null || Array.isArray(v) || Object.keys(v).length !== 3 || v.format !== "iss_sub"
        || typeof v.iss !== "string" || v.iss === "" || typeof v.sub !== "string" || v.sub === "") {
        throw new VerificationError("malformed");
      }
      subId = { format: "iss_sub", iss: v.iss, sub: v.sub };
    }
    // LAST, after every other check: the record is the atomic step, an insert-if-absent on (iss, jti).
    // The record lives through the last accepted second, exp + 60 s inclusive: a whole number of seconds, at least 1.
    if (!(await this.#o.replayStore.setIfAbsent(`${this.#o.issuer}\u0000${jti}`, exp + SKEW - at + 1, at))) {
      throw new VerificationError("replay");
    }
    const id: Identity = { tenant, adopter: this.#o.adopter };
    for (const k of ["sub", "grant", "persona", "act_kind", "presence", "run_id"] as const) {
      const v = str(k);
      if (v !== undefined) id[k] = v;
    }
    if (Array.isArray(c.scopes)) id.scopes = c.scopes.filter((s): s is string => typeof s === "string");
    if (c.approved_by !== undefined) id.approved_by = c.approved_by;
    if (c.probe === true) id.probe = true;
    if (subId) id.sub_id = subId;
    return id;
  }
}

// @varketa/verify-acting-principal: verify the Varketa-Acting-Principal header, claim set versions 3, 4, 5 and 6.
// The normative half is ../../SPEC.md and ../../vectors/v6; this file follows the spec's order.
import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";
import { toUSVString } from "node:util";

export const HEADER = "Varketa-Acting-Principal";
export const TYP = "varketa-acting-principal+jwt";
export const SUPPORTED_VERSIONS: readonly number[] = [3, 4, 5, 6];
// `size` is the byte length of each public coordinate (EC: x and y; Ed25519: x alone).
const ALGORITHMS: Record<string, { hash: string | null; kty: string; crv: string; size: number }> = {
  ES256: { hash: "sha256", kty: "EC", crv: "P-256", size: 32 },
  ES384: { hash: "sha384", kty: "EC", crv: "P-384", size: 48 },
  EdDSA: { hash: null, kty: "OKP", crv: "Ed25519", size: 32 },
};
const SKEW = 60;
const MAX_LIFETIME = 120;
const MAX_CACHE = 300;
const REFETCH_INTERVAL = 60;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_DOCUMENT_BYTES = 64 * 1024;
const MAX_ASSERTION_DEPTH = 32;
const MAX_APPROVAL_LINKS = 8;
// Unicode 17.0 White_Space, pinned to keep the wire rule independent of runtime trim behavior.
const NON_WHITESPACE = /[^\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u;
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
 * Return false only for a conflict. Throw if the result is unknown, including when a write loses its acknowledgement.
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
  /** Finite seconds since the epoch. Defaults to the system clock. */
  clock?: () => number;
  fetchDocument?: FetchDocument;
  /** Maps the URL as received to the URL the caller sent, after this API's own proxies. Defaults to identity. */
  requestUrl?: (url: string) => string;
}

/** The caller as the adopter's own identity provider names it: RFC 9493's iss_sub subject identifier. */
export interface SubjectId { format: "iss_sub"; iss: string; sub: string }

/** The actor performing a customer's own act (act_kind on_behalf): RFC 8693's act, the adopter's backend. */
export interface Actor { sub: string; iss: string }

/** The person accountable for a run (claim set 6), never its actor: `sub` as this adopter receives it on that person's
 * own acts, and `sub_id` the adopter's own subject for the run-as grant, where Varketa holds one. */
export interface RunOwner { sub: string; sub_id?: SubjectId }

export interface Identity {
  sub?: string; grant?: string; tenant: string; adopter: string; persona?: string; scopes?: string[];
  act_kind?: string; presence?: string; run_id?: string; approved_by?: unknown; probe?: true;
  sub_id?: SubjectId; act?: Actor; run_owner?: RunOwner;
}

export interface Request { method: string; url: string; body: Uint8Array | string; assertion: string | null | undefined }

// A bounded fetch: no redirect, 10 s for the whole document, and at most 64 KiB (SPEC §2.5).
const defaultFetch: FetchDocument = async (url) => {
  const deadline = performance.now() + FETCH_TIMEOUT_MS;
  const remaining = deadline - performance.now();
  if (remaining <= 0) throw new Error(`${url}: no time left to fetch`);
  const signal = AbortSignal.timeout(Math.ceil(remaining));
  const r = await fetch(url, { redirect: "error", headers: { accept: "application/json" }, signal });
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of r.body ?? []) {
    size += chunk.length;
    if (size > MAX_DOCUMENT_BYTES) throw new Error(`${url}: document over ${MAX_DOCUMENT_BYTES} bytes`);
    chunks.push(chunk);
  }
  const document = { status: r.status, cacheControl: r.headers.get("cache-control"),
    body: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)) };
  // The abort timer can still be waiting to run when the stream completes.
  if (performance.now() >= deadline) throw new Error(`${url}: no complete answer within ${FETCH_TIMEOUT_MS} ms`);
  return document;
};

function maxAge(cacheControl: string | null): number {
  // HTTP's own grammar, as in the Python verifier: optional whitespace is space or tab, and digits are ASCII.
  const m = /(?:^|,)[ \t]*max-age=([0-9]+)/i.exec(cacheControl ?? "");
  return m ? Math.min(Number(m[1]), MAX_CACHE) : 0;
}

function b64url(s: string): Buffer {
  if (/[^A-Za-z0-9_-]/.test(s) || s.length % 4 === 1) throw new VerificationError("malformed");
  return Buffer.from(s, "base64url");
}

// Bound native parser nesting. The native parser still checks JSON syntax.
function hasBoundedAssertionDepth(text: string): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i++;
      else if (ch === '"') inString = false;
    } else if (ch === '"') {
      inString = true;
    } else if (ch === "{" || ch === "[") {
      if (++depth > MAX_ASSERTION_DEPTH) return false;
    } else if (ch === "}" || ch === "]") {
      depth--;
    }
  }
  return true;
}

// After JSON syntax validation, every backslash begins an escape inside a string.
// Scan the source so a duplicate name cannot hide a malformed earlier value.
function hasScalarEscapes(text: string): boolean {
  let offset = 0;
  while (true) {
    offset = text.indexOf("\\", offset);
    if (offset === -1) return true;
    if (text[offset + 1] !== "u") {
      offset += 2;
      continue;
    }
    const unit = Number.parseInt(text.slice(offset + 2, offset + 6), 16);
    offset += 6;
    if (unit < 0xd800 || unit > 0xdfff) continue;
    if (unit >= 0xdc00 || !text.startsWith("\\u", offset)) return false;
    const low = Number.parseInt(text.slice(offset + 2, offset + 6), 16);
    if (low < 0xdc00 || low > 0xdfff) return false;
    offset += 6;
  }
}

function json(b: Buffer, kind: "document" | "assertion" = "document"): Record<string, unknown> {
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
    if (kind === "assertion" && !hasBoundedAssertionDepth(text)) throw new Error();
    const v = JSON.parse(text);
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error();
    if (kind === "assertion" && !hasScalarEscapes(text)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new VerificationError("malformed");
  }
}

function isApprovalChain(link: unknown): boolean {
  for (let i = 0; i < MAX_APPROVAL_LINKS; i++) {
    if (link === null || typeof link !== "object" || Array.isArray(link)) return false;
    const value = link as Record<string, unknown>;
    if (!Object.hasOwn(value, "sub") || typeof value.sub !== "string" || !NON_WHITESPACE.test(value.sub)) return false;
    const hasNext = Object.hasOwn(value, "act");
    if (Object.keys(value).length !== (hasNext ? 2 : 1)) return false;
    if (!hasNext) return true;
    link = value.act;
  }
  return false;
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
    let jwksUri = this.#jwksUri;
    let metadataMaxAge: number | undefined;
    if (jwksUri === "" || now - this.#mdFetchedAt >= this.#mdMaxAge) {
      const md = await this.#get(this.#o.issuer + METADATA_PATH);
      if (!md) return false;
      let doc: Record<string, unknown>;
      try { doc = json(Buffer.from(md.body)); } catch { return false; }
      if (doc.issuer !== this.#o.issuer || typeof doc.jwks_uri !== "string" || !doc.jwks_uri.startsWith("https://")) return false;
      jwksUri = doc.jwks_uri;
      metadataMaxAge = maxAge(md.cacheControl);
    }
    const r = await this.#get(jwksUri);
    let keys: unknown;
    try { keys = r && json(Buffer.from(r.body)).keys; } catch { keys = undefined; }
    // Publish refreshed metadata only with the key set fetched through it. Failure leaves the prior snapshot intact,
    // including its expiry. An unknown kid's failed refetch therefore leaves an unexpired snapshot usable (SPEC §2.3).
    if (!r || !Array.isArray(keys)) return false;
    const keyMap = new Map(keys.filter((k) => k && typeof k.kid === "string").map((k) => [k.kid as string, k]));
    const keyMaxAge = maxAge(r.cacheControl);
    if (metadataMaxAge !== undefined) {
      this.#jwksUri = jwksUri;
      this.#mdFetchedAt = now;
      this.#mdMaxAge = metadataMaxAge;
    }
    this.#keys = keyMap;
    this.#fetchedAt = now;
    this.#maxAge = keyMaxAge;
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

  #readClock(): number {
    const now = this.#clock();
    if (!Number.isFinite(now)) throw new Error("verify-acting-principal: clock must return finite epoch seconds");
    return now;
  }

  /** Returns the verified identity. Ordered refusals use VerificationError. Callback and store errors may propagate. */
  async verify(req: Request): Promise<Identity> {
    const now = this.#readClock();
    const parts = (req.assertion ?? "").split(".");
    if (parts.length !== 3) throw new VerificationError("malformed");
    const header = json(b64url(parts[0]), "assertion");
    if (header.typ !== TYP) throw new VerificationError("typ");
    const alg = typeof header.alg === "string" ? ALGORITHMS[header.alg] : undefined;
    if (!alg || !Object.hasOwn(ALGORITHMS, header.alg as string)) throw new VerificationError("alg");
    if (this.#keys === null || now - this.#fetchedAt >= this.#maxAge || now - this.#mdFetchedAt >= this.#mdMaxAge) {
      if (!(await this.#load(now))) throw new VerificationError("jwks_unavailable");
    }
    const kid = typeof header.kid === "string" ? header.kid : "";
    let jwk = this.#keys?.get(kid);
    // A refetch already in flight (another request's, for a rotated-in kid) may bring this kid: wait for it rather than
    // refuse, as the Python verifier's shared flight does.
    if (!jwk && this.#loading) {
      await this.#loading.catch(() => false);
      jwk = this.#keys?.get(kid);
    }
    if (!jwk && (this.#lastRefetch === null || now - this.#lastRefetch >= REFETCH_INTERVAL)) {
      this.#lastRefetch = now;
      if (await this.#load(now)) jwk = this.#keys?.get(kid);
    }
    // A network wait may itself consume the documents' positive cache lifetime.
    const keyAt = this.#readClock();
    if ((this.#mdMaxAge > 0 && keyAt - this.#mdFetchedAt >= this.#mdMaxAge) ||
        (this.#maxAge > 0 && keyAt - this.#fetchedAt >= this.#maxAge)) throw new VerificationError("jwks_unavailable");
    if (!jwk) throw new VerificationError("kid");
    // A signature part that is not base64url is malformed before the key's type is judged, as in the Python verifier.
    const sig = b64url(parts[2]);
    let key: KeyObject;
    try {
      if (jwk.kty !== alg.kty || jwk.crv !== alg.crv || (jwk.alg !== undefined && jwk.alg !== header.alg)) throw new Error();
      // Each coordinate is this file's own base64url of exactly the curve's size, as the Python verifier holds it:
      // createPublicKey alone takes a padded or over-long coordinate, so the two libraries judged one key differently.
      for (const name of alg.kty === "EC" ? ["x", "y"] : ["x"]) {
        const coordinate = jwk[name];
        if (typeof coordinate !== "string" || b64url(coordinate).length !== alg.size) throw new Error();
      }
      key = createPublicKey({ key: jwk as never, format: "jwk" });
    } catch {
      throw new VerificationError("signature");
    }
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    const ok = alg.hash === null
      ? verifySignature(null, signed, key, sig)
      : verifySignature(alg.hash, signed, { key, dsaEncoding: "ieee-p1363" }, sig);
    if (!ok) throw new VerificationError("signature");
    const c = json(b64url(parts[1]), "assertion");
    // The clock again, after any key-set wait: the time checks and the replay record's lifetime use it.
    const at = this.#readClock();
    const str = (k: string) => (typeof c[k] === "string" ? (c[k] as string) : undefined);
    // Integers only: a fractional ver, iat or exp is not truncated to a known value; it is absent.
    const num = (k: string) => (Number.isSafeInteger(c[k]) ? (c[k] as number) : undefined);
    const iat = num("iat"), exp = num("exp");
    // Snapshot caller-owned bytes before requestUrl can run. Judge text encoding at the body check.
    const suppliedBody = req.body;
    const body = typeof suppliedBody === "string" ? suppliedBody : Buffer.from(suppliedBody);
    if (str("iss") !== this.#o.issuer) throw new VerificationError("iss");
    const ver = num("ver");
    if (ver === undefined || !SUPPORTED_VERSIONS.includes(ver)) throw new VerificationError("ver");
    if (str("adopter") !== this.#o.adopter) throw new VerificationError("adopter");
    if (str("aud") !== this.#o.audience) throw new VerificationError("aud");
    if (iat === undefined || iat > at + SKEW) throw new VerificationError("not_yet_valid");
    if (exp === undefined || at > exp + SKEW) throw new VerificationError("expired");
    if (exp - iat > MAX_LIFETIME) throw new VerificationError("lifetime");
    if (str("htm") !== req.method) throw new VerificationError("htm");
    if (str("htu") !== this.#requestUrl(req.url)) throw new VerificationError("htu");
    if (typeof body === "string" && toUSVString(body) !== body) throw new VerificationError("bdy");
    const raw = typeof body === "string" ? Buffer.from(body, "utf8") : body;
    if (str("bdy") !== createHash("sha256").update(raw).digest("base64url")) throw new VerificationError("bdy");
    const jti = str("jti"), tenant = str("tenant");
    // The claims Varketa never omits and an API authorizes on: the jti, the tenant, and the subject or grant.
    if (!jti || !tenant || (!str("sub") && !str("grant"))) throw new VerificationError("malformed");
    // A PRESENT sub_id is exactly RFC 9493's iss_sub, its iss and sub non-empty strings, or the assertion is malformed:
    // a verifier never exposes half a subject.
    const issSub = (u: unknown): SubjectId => {
      const v = u as Record<string, unknown> | null;
      if (typeof v !== "object" || v === null || Array.isArray(v) || Object.keys(v).length !== 3 || v.format !== "iss_sub"
        || typeof v.iss !== "string" || v.iss === "" || typeof v.sub !== "string" || v.sub === "") {
        throw new VerificationError("malformed");
      }
      return { format: "iss_sub", iss: v.iss, sub: v.sub };
    };
    const subId = Object.hasOwn(c, "sub_id") ? issSub(c.sub_id) : undefined;
    // A PRESENT run_owner names a run's owner, and only a run's: exactly {sub} or {sub, sub_id}, sub a non-empty string
    // and sub_id an exact iss_sub, beside a run_id, whatever the act_kind.
    let runOwner: RunOwner | undefined;
    if (Object.hasOwn(c, "run_owner")) {
      const v = c.run_owner as Record<string, unknown> | null;
      if (typeof v !== "object" || v === null || Array.isArray(v) || !str("run_id") || typeof v.sub !== "string"
        || v.sub === "" || Object.keys(v).length !== (Object.hasOwn(v, "sub_id") ? 2 : 1)) {
        throw new VerificationError("malformed");
      }
      runOwner = { sub: v.sub };
      if (Object.hasOwn(v, "sub_id")) runOwner.sub_id = issSub(v.sub_id);
    }
    const actKind = str("act_kind");
    // A kind or claim newer than the signed claim set is malformed: discovery and on_behalf need 5, watch_run and run_owner 6.
    if ((ver < 5 && (actKind === "discovery" || actKind === "on_behalf"))
      || (ver < 6 && (actKind === "watch_run" || runOwner !== undefined))) throw new VerificationError("malformed");
    // A PRESENT act is exactly RFC 8693's {sub, iss}, both non-empty strings, and on_behalf is the one act_kind that
    // carries it and must: a verifier never exposes half an actor, nor an actor on a kind that has none.
    let actor: Actor | undefined;
    if (Object.hasOwn(c, "act") !== (actKind === "on_behalf")) throw new VerificationError("malformed");
    if (Object.hasOwn(c, "act")) {
      const v = c.act as Record<string, unknown> | null;
      if (typeof v !== "object" || v === null || Array.isArray(v) || Object.keys(v).length !== 2
        || typeof v.sub !== "string" || v.sub === "" || typeof v.iss !== "string" || v.iss === "") {
        throw new VerificationError("malformed");
      }
      actor = { sub: v.sub, iss: v.iss };
    }
    const hasApproval = Object.hasOwn(c, "approved_by");
    if (hasApproval && !isApprovalChain(c.approved_by)) throw new VerificationError("malformed");
    // LAST, after every other check: the record is the atomic step, an insert-if-absent on (iss, jti).
    // The exclusive expiry must lie past the inclusive cutoff, including when floating-point addition rounds.
    const cutoff = exp + SKEW;
    const ttl = cutoff - at + 1;
    const expiry = at + ttl;
    if (!Number.isFinite(ttl) || !Number.isFinite(expiry) || expiry <= cutoff) {
      throw new Error("verify-acting-principal: replay expiry cannot outlast the assertion");
    }
    if (!(await this.#o.replayStore.setIfAbsent(`${this.#o.issuer}\u0000${jti}`, ttl, at))) {
      throw new VerificationError("replay");
    }
    const id: Identity = { tenant, adopter: this.#o.adopter };
    for (const k of ["sub", "grant", "persona", "act_kind", "presence", "run_id"] as const) {
      const v = str(k);
      if (v !== undefined) id[k] = v;
    }
    if (Array.isArray(c.scopes)) id.scopes = c.scopes.filter((s): s is string => typeof s === "string");
    if (hasApproval) id.approved_by = c.approved_by;
    if (c.probe === true) id.probe = true;
    if (subId) id.sub_id = subId;
    if (actor) id.act = actor;
    if (runOwner) id.run_owner = runOwner;
    return id;
  }
}

import { createPrivateKey, createPublicKey, randomUUID, type KeyObject } from "node:crypto";
import { jwkThumbprint, publicJwk, signEs256, type EcJwk } from "./dpop.ts";

/** A public signing key as the backend's key set serves it. */
export type Jwk = EcJwk & { kid: string; alg: "ES256"; use: "sig" };

/** Signs for the backend when its key lives elsewhere (a KMS, an HSM). `sign` returns the raw ES256 signature
 * (r || s, 64 bytes) over `input`. */
export interface Es256Signer {
  publicJwk: EcJwk;
  sign(input: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

/** Only the public members of a P-256 key, whatever else the caller passed. */
function publicOnly(k: { kty?: unknown; crv?: unknown; x?: unknown; y?: unknown }): EcJwk {
  if (k.kty !== "EC" || k.crv !== "P-256" || typeof k.x !== "string" || typeof k.y !== "string") {
    throw new Error("a backend key is not a P-256 public key");
  }
  return { kty: "EC", crv: "P-256", x: k.x, y: k.y };
}

const asJwk = (k: EcJwk): Jwk => ({ ...k, kid: jwkThumbprint(k), alg: "ES256", use: "sig" });

/** The adopter's backend as an asserted identity of its own (hop 1): it signs the subject token of its own
 * exchange with a key whose public half Varketa's admission of this issuer reads from `jwks()`. */
export class BackendIdentity {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  readonly kid: string;
  readonly #key: KeyObject | null;
  readonly #signer: Es256Signer | null;
  readonly #keys: Jwk[];

  constructor(o: {
    issuer: string;
    subject: string;
    audience: string;
    privateKeyPem?: string;
    signer?: Es256Signer;
    /** Keys still served while Varketa may hold a cached key set, as after a rotation. */
    previousKeys?: EcJwk[];
  }) {
    if ((o.privateKeyPem === undefined) === (o.signer === undefined)) {
      throw new Error("BackendIdentity takes privateKeyPem or signer, exactly one");
    }
    this.issuer = o.issuer;
    this.subject = o.subject;
    this.audience = o.audience;
    this.#key = o.privateKeyPem !== undefined ? createPrivateKey(o.privateKeyPem) : null;
    this.#signer = o.signer ?? null;
    const current = this.#key !== null ? publicJwk(createPublicKey(this.#key)) : publicOnly(o.signer!.publicJwk);
    this.kid = jwkThumbprint(current);
    const previous = (o.previousKeys ?? []).map(publicOnly).map(asJwk).filter((k) => k.kid !== this.kid);
    this.#keys = [asJwk(current), ...previous];
  }

  /** A one-minute assertion with a fresh `jti`, which Varketa's exchange spends once. */
  async assertion(nowSeconds: number): Promise<string> {
    const header = { alg: "ES256", typ: "JWT", kid: this.kid };
    const payload = {
      iss: this.issuer,
      sub: this.subject,
      aud: this.audience,
      iat: nowSeconds,
      nbf: nowSeconds - 5,
      exp: nowSeconds + 60,
      jti: randomUUID(),
    };
    if (this.#key !== null) return signEs256(header, payload, this.#key);
    const input = `${b64(header)}.${b64(payload)}`;
    const sig = await this.#signer!.sign(Buffer.from(input));
    if (sig.length !== 64) throw new Error("the signer did not return a 64-byte ES256 signature");
    return `${input}.${Buffer.from(sig).toString("base64url")}`;
  }

  /** The key set Varketa's admission reads: public members only, the current key first. */
  jwks(): { keys: Jwk[] } {
    return { keys: this.#keys.map((k) => ({ ...k })) };
  }
}

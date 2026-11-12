import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

/** The public half of an ES256 key as a JWK. */
export interface EcJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

/** RFC 7638's thumbprint of a P-256 public key: what a DPoP-bound token's `cnf.jkt` names. */
export function jwkThumbprint(jwk: EcJwk): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash("sha256").update(canonical).digest("base64url");
}

export function publicJwk(key: KeyObject): EcJwk {
  const j = key.export({ format: "jwk" }) as { kty?: string; crv?: string; x?: string; y?: string };
  if (j.kty !== "EC" || j.crv !== "P-256" || !j.x || !j.y) throw new Error("the key is not a P-256 key");
  return { kty: "EC", crv: "P-256", x: j.x, y: j.y };
}

/** Signs a compact JWS with an ES256 private key. */
export function signEs256(header: Record<string, unknown>, payload: Record<string, unknown>, key: KeyObject): string {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

/** A DPoP key (RFC 9449): the proof-of-possession key every token the backend obtains is bound to. */
export class DpopKey {
  readonly #private: KeyObject;
  readonly jwk: EcJwk;

  constructor(privateKey: KeyObject, publicKey: KeyObject) {
    this.#private = privateKey;
    this.jwk = publicJwk(publicKey);
  }

  static generate(): DpopKey {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return new DpopKey(privateKey, publicKey);
  }

  get thumbprint(): string {
    return jwkThumbprint(this.jwk);
  }

  /** A proof for one request. `accessToken` adds `ath` (a resource request); `nonce` answers a server's DPoP-Nonce. */
  proof(htm: string, url: string, opts: { accessToken?: string; nonce?: string } = {}): string {
    const u = new URL(url);
    const payload: Record<string, unknown> = {
      jti: randomUUID(),
      htm,
      htu: `${u.origin}${u.pathname}`,
      iat: Math.floor(Date.now() / 1000),
    };
    if (opts.accessToken !== undefined) {
      payload.ath = createHash("sha256").update(opts.accessToken).digest("base64url");
    }
    if (opts.nonce !== undefined) payload.nonce = opts.nonce;
    return signEs256({ typ: "dpop+jwt", alg: "ES256", jwk: this.jwk }, payload, this.#private);
  }
}

// The deployed-JWKS discovery check: run by hand (`npm run discovery`), never in CI, since it reads the network.
// It proves DISCOVERY interop with an issuer's deployed metadata and key set: issuer, jwks_uri, each key's kid, alg,
// use, and a kty and crv matching its alg that parse as a public key; each document within the library's 10 s and
// 64 KiB, with a max-age (read as the library reads it) of 1 to 300 s. It is NOT a signature by that issuer's key, which no test can hold. Its
// one negative: an assertion under a kid the deployed set does not hold is refused `kid`, after one fresh refetch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { Verifier, InMemoryReplayStore, VerificationError, METADATA_PATH, SUPPORTED_VERSIONS, TYP } from "../src/index.ts";

const issuer = process.env.VARKETA_ISSUER ?? "https://api.varketa.ai";

// The library's bounds and grammar, restated here because its defaults are not exported.
const MAX_DOCUMENT_BYTES = 64 * 1024;
const KEY_TYPES: Record<string, { kty: string; crv: string }> = {
  ES256: { kty: "EC", crv: "P-256" }, ES384: { kty: "EC", crv: "P-384" }, EdDSA: { kty: "OKP", crv: "Ed25519" },
};

// One fetch as the library's default makes it: no redirect, 10 s, at most 64 KiB.
async function fetchBounded(url: string) {
  const r = await fetch(url, { redirect: "error", headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000) });
  const body = await r.text();
  assert.ok(Buffer.byteLength(body) <= MAX_DOCUMENT_BYTES, `${url} is over ${MAX_DOCUMENT_BYTES} bytes`);
  return { status: r.status, cacheControl: r.headers.get("cache-control"), body };
}

async function get(url: string) {
  const r = await fetchBounded(url);
  assert.equal(r.status, 200, url);
  const maxAge = /(?:^|,)[ \t]*max-age=([0-9]+)/i.exec(r.cacheControl ?? "");
  assert.ok(maxAge && Number(maxAge[1]) >= 1 && Number(maxAge[1]) <= 300, `${url} Cache-Control max-age must be 1 to 300 s`);
  return JSON.parse(r.body);
}

test(`the deployed metadata and key set at ${issuer} are what the spec reads`, async () => {
  const md = await get(issuer + METADATA_PATH);
  assert.equal(md.issuer, issuer);
  assert.ok(typeof md.jwks_uri === "string" && md.jwks_uri.startsWith("https://"), `jwks_uri ${md.jwks_uri}`);
  assert.ok(md.signing_alg_values_supported.every((a: string) => ["ES256", "ES384", "EdDSA"].includes(a)));
  // Every claim set the issuer signs is one this library accepts.
  assert.ok(Array.isArray(md.ver_values_supported) && md.ver_values_supported.length >= 1 &&
    md.ver_values_supported.every((n: number) => SUPPORTED_VERSIONS.includes(n)), `ver_values_supported ${md.ver_values_supported}`);
  const jwks = await get(md.jwks_uri);
  assert.ok(Array.isArray(jwks.keys) && jwks.keys.length >= 1);
  assert.equal(new Set(jwks.keys.map((k: { kid: unknown }) => k.kid)).size, jwks.keys.length, "each kid once");
  for (const k of jwks.keys) {
    assert.equal(typeof k.kid, "string");
    assert.ok(Object.hasOwn(KEY_TYPES, k.alg), `kid ${k.kid} alg ${k.alg}`);
    assert.equal(k.use, "sig");
    assert.equal(k.d, undefined, `kid ${k.kid} publishes a private member`);
    // The verifier refuses a key whose kty or crv does not match its alg, or that does not parse, as signature.
    assert.deepEqual({ kty: k.kty, crv: k.crv }, KEY_TYPES[k.alg], `kid ${k.kid} kty/crv for ${k.alg}`);
    assert.doesNotThrow(() => createPublicKey({ key: k, format: "jwk" }), `kid ${k.kid} parses`);
  }
});

test(`an unknown kid is refused against the deployed key set at ${issuer}`, async () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const head = enc({ alg: "ES256", kid: "discovery-check-unknown-kid", typ: TYP });
  const now = Math.floor(Date.now() / 1000);
  const body = enc({ ver: SUPPORTED_VERSIONS.at(-1), iss: issuer, iat: now, exp: now + 60, jti: `discovery-${now}` });
  const sig = sign("sha256", Buffer.from(`${head}.${body}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
  // A counting fetch (the library's default bounds, fetchBounded; the default is not exported), so the one fresh
  // refetch on the unknown kid is asserted.
  let jwksFetches = 0;
  const md = await get(issuer + METADATA_PATH);
  const v = new Verifier({ issuer, adopter: "discovery-check", audience: "https://discovery-check.invalid",
    replayStore: new InMemoryReplayStore({ singleInstance: true }),
    fetchDocument: async (url) => {
      if (url === md.jwks_uri) jwksFetches++;
      return fetchBounded(url);
    } });
  await assert.rejects(v.verify({ method: "GET", url: "https://discovery-check.invalid/", body: "",
    assertion: `${head}.${body}.${sig.toString("base64url")}` }), (e) => e instanceof VerificationError && e.code === "kid");
  assert.equal(jwksFetches, 2, "one load and one fresh refetch on the unknown kid");
});

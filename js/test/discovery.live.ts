// The deployed-JWKS discovery check: run by hand (`npm run discovery`), never in CI, since it reads the network.
// It proves DISCOVERY interop with an issuer's deployed metadata and key set: issuer, jwks_uri, each key's kid, alg
// and use, and a max-age of at most 300 s. It is NOT a signature by that issuer's key, which no test can hold. Its
// one negative: an assertion under a kid the deployed set does not hold is refused `kid`, after one fresh refetch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { Verifier, InMemoryReplayStore, VerificationError, METADATA_PATH, TYP } from "../src/index.ts";

const issuer = process.env.VARKETA_ISSUER ?? "https://api.varketa.ai";

async function get(url: string) {
  const r = await fetch(url, { redirect: "error", headers: { accept: "application/json" } });
  assert.equal(r.status, 200, url);
  const maxAge = /max-age=(\d+)/i.exec(r.headers.get("cache-control") ?? "");
  assert.ok(maxAge && Number(maxAge[1]) <= 300, `${url} Cache-Control max-age must be at most 300 s`);
  return r.json();
}

test(`the deployed metadata and key set at ${issuer} are what the spec reads`, async () => {
  const md = await get(issuer + METADATA_PATH);
  assert.equal(md.issuer, issuer);
  assert.ok(typeof md.jwks_uri === "string" && md.jwks_uri.startsWith("https://"), `jwks_uri ${md.jwks_uri}`);
  assert.ok(md.signing_alg_values_supported.every((a: string) => ["ES256", "ES384", "EdDSA"].includes(a)));
  assert.ok(md.ver_values_supported.includes(3));
  const jwks = await get(md.jwks_uri);
  assert.ok(Array.isArray(jwks.keys) && jwks.keys.length >= 1);
  for (const k of jwks.keys) {
    assert.equal(typeof k.kid, "string");
    assert.ok(["ES256", "ES384", "EdDSA"].includes(k.alg), `kid ${k.kid} alg ${k.alg}`);
    assert.equal(k.use, "sig");
    assert.equal(k.d, undefined, `kid ${k.kid} publishes a private member`);
  }
});

test(`an unknown kid is refused against the deployed key set at ${issuer}`, async () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const head = enc({ alg: "ES256", kid: "discovery-check-unknown-kid", typ: TYP });
  const now = Math.floor(Date.now() / 1000);
  const body = enc({ ver: 3, iss: issuer, iat: now, exp: now + 60, jti: `discovery-${now}` });
  const sig = sign("sha256", Buffer.from(`${head}.${body}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
  // A counting fetch (no redirect, 10 s, as the library's default; the default is not exported), so the one fresh
  // refetch on the unknown kid is asserted.
  let jwksFetches = 0;
  const md = await get(issuer + METADATA_PATH);
  const v = new Verifier({ issuer, adopter: "discovery-check", audience: "https://discovery-check.invalid",
    replayStore: new InMemoryReplayStore({ singleInstance: true }),
    fetchDocument: async (url) => {
      if (url === md.jwks_uri) jwksFetches++;
      const r = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(10_000) });
      return { status: r.status, cacheControl: r.headers.get("cache-control"), body: await r.text() };
    } });
  await assert.rejects(v.verify({ method: "GET", url: "https://discovery-check.invalid/", body: "",
    assertion: `${head}.${body}.${sig.toString("base64url")}` }), (e) => e instanceof VerificationError && e.code === "kid");
  assert.equal(jwksFetches, 2, "one load and one fresh refetch on the unknown kid");
});

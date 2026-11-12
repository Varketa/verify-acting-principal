import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { inspect } from "node:util";
import { BackendIdentity, OnBehalfError, type EcJwk } from "../src/index.ts";
import { BACKEND, MCP } from "./fake/varketa.ts";
import { setup } from "./fake/setup.ts";

const A = { key: "sess_a" };
const B = { key: "sess_b" };
const rpc = { method: "POST", headers: { "content-type": "application/json" }, body: '{"jsonrpc":"2.0","id":1}' };

/** A run through every path: hops, reuse, nonce retries, refusals, fresh mints and door requests. */
async function everyPath() {
  const s = setup();
  const { kit, fake } = s;
  fake.once("backend", { status: 400, headers: { "dpop-nonce": "as-n" }, body: { error: "use_dpop_nonce" } });
  fake.once("customer", { status: 400, headers: { "dpop-nonce": "as-n" }, body: { error: "use_dpop_nonce" } });
  const f = await kit.fetchFor(A);
  fake.once("door", { status: 401, headers: { "dpop-nonce": "n", "www-authenticate": 'DPoP error="use_dpop_nonce"' } });
  await f(MCP, rpc);
  fake.once("door", { status: 401, headers: { "www-authenticate": 'DPoP error="invalid_token"' } });
  await f(MCP, rpc);
  await f(MCP, { method: "GET" });
  await f(MCP, { method: "DELETE" });
  fake.once("customer", { status: 503 });
  await assert.rejects(kit.credentialFor(B));
  fake.once("customer", { status: 400, body: { error: "invalid_grant", error_description: "actor_token_not_usable" } });
  await assert.rejects(kit.credentialFor(B));
  await kit.credentialFor(B);
  const g = await kit.fetchFor(B, { fresh: true });
  await g(MCP, rpc);
  return s;
}

test("no fallback arm is ever sent, and the IdP token goes to hop 2 only", async () => {
  const { fake } = await everyPath();
  const actors = new Set<string>();
  for (const r of fake.requests) {
    const text = JSON.stringify(r);
    assert.ok(!/component|parent_origin/.test(text), `a frame-exchange field in ${r.url}`);
    assert.ok(!/^bearer /i.test(r.headers.authorization ?? ""), "no bearer token anywhere");
    if (r.step === "backend") assert.equal(r.form?.actor_token, undefined, "hop 1 is the backend as itself only");
    if (r.step === "customer") actors.add(r.form?.actor_token ?? "");
  }
  assert.ok(actors.size >= 1);
  for (const r of fake.requests) {
    // Hop 1's session is only ever an actor_token in hop 2: never an authorization, never a door token's subject.
    for (const a of actors) {
      if (r.step === "customer") continue;
      assert.ok(!JSON.stringify(r).includes(a), `the backend's session ${a} reached ${r.step}`);
    }
  }
  assert.ok(fake.subjects.length >= 4);
  for (const s of fake.subjects) {
    const carriers = fake.requests.filter(
      (r) =>
        [...Object.values(r.form ?? {}), ...Object.values(r.headers), r.url].includes(s) ||
        (r.step === "door" && (r.body ?? "").includes(s)),
    );
    assert.ok(carriers.length <= 1, `subject ${s} sent ${carriers.length} times`);
    for (const r of carriers) {
      assert.equal(r.step, "customer");
      assert.equal(r.form?.subject_token, s);
    }
  }
  fake.done();
});

test("no private key is in any request, credential, key set, error or the kit itself", async () => {
  const { kit, fake, pem } = await everyPath();
  const d = (createPrivateKey(pem).export({ format: "jwk" }) as { d: string }).d;
  const outputs = [
    JSON.stringify(fake.requests),
    JSON.stringify(kit.jwks()),
    inspect(kit, { depth: 10, showHidden: true }),
    inspect(await kit.credentialFor(A), { depth: 10, showHidden: true }),
    JSON.stringify(await kit.credentialFor(A)),
    inspect(new OnBehalfError("door", 401, "invalid_token"), { depth: 10 }),
  ];
  for (const o of outputs) {
    assert.ok(!o.includes(d), "the backend's private key leaked");
    assert.ok(!/"d"\s*:/.test(o) && !/\bd: '/.test(o), "a private JWK member leaked");
    assert.ok(!o.includes("PRIVATE KEY"), "a PEM leaked");
  }
  for (const r of fake.requests) {
    const jwk = r.proof?.header.jwk as Record<string, unknown>;
    assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x", "y"]);
  }
  fake.done();
});

test("the key set holds public keys only, the current one first, and a previous key for rotation", () => {
  const prev = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const pem = generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey.export({ format: "pem", type: "pkcs8" })
    .toString();
  // A previous key passed with its private member is served without it.
  const backend = new BackendIdentity({ ...BACKEND, privateKeyPem: pem, previousKeys: [prev as unknown as EcJwk] });
  const keys = backend.jwks().keys;
  assert.equal(keys.length, 2);
  assert.equal(keys[0]?.kid, backend.kid);
  for (const k of keys) assert.deepEqual(Object.keys(k).sort(), ["alg", "crv", "kid", "kty", "use", "x", "y"]);
  assert.equal(keys[1]?.x, prev.x);
  const one = new BackendIdentity({ ...BACKEND, privateKeyPem: pem });
  assert.equal(one.jwks().keys.length, 1);
});

test("a signer hook signs the assertion, and its key is the one served", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { sign } = await import("node:crypto");
  const jwk = publicKey.export({ format: "jwk" }) as EcJwk;
  const backend = new BackendIdentity({
    ...BACKEND,
    signer: {
      publicJwk: jwk,
      sign: async (input) => sign("sha256", input, { key: privateKey, dsaEncoding: "ieee-p1363" }),
    },
  });
  const { kit, fake } = setup({ backend });
  await kit.credentialFor(A); // the fake verifies the assertion under kit.jwks()
  assert.equal(kit.jwks().keys[0]?.x, jwk.x);
  assert.throws(() => new BackendIdentity({ ...BACKEND }), /exactly one/);
  fake.done();
});

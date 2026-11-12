import { test } from "node:test";
import assert from "node:assert/strict";
import { BackendIdentity, OnBehalfError, classify, type EcJwk } from "../src/index.ts";
import { clerkSubjectTokens } from "../src/clerk.ts";
import { CLERK_API, type Answer, type Step } from "./fake/varketa.ts";
import { hops, setup } from "./fake/setup.ts";

const A = { key: "sess_a" };
const B = { key: "sess_b" };
const MINT_A = ["as:backend", "subject:sess_a", "as:customer", "as:door_token"];

test("the backend exchanges as itself, then for the customer with itself as actor, then for the door", async () => {
  const { kit, fake } = setup();
  const cred = await kit.credentialFor(A);
  assert.match(cred.accessToken, /^door_token-/);
  assert.deepEqual(fake.log, MINT_A);
  assert.equal(fake.jkts.size, 1, "one DPoP key binds every token");
  assert.deepEqual(Object.keys(cred).sort(), ["accessToken", "proof"]);
  fake.done();
});

test("a live credential is reused; another customer reuses the backend's session; expiry mints afresh", async () => {
  const { kit, fake, advance } = setup();
  const first = await kit.credentialFor(A);
  fake.log.length = 0;
  assert.equal((await kit.credentialFor(A)).accessToken, first.accessToken);
  assert.deepEqual(fake.log, []);
  await kit.credentialFor(B);
  assert.deepEqual(fake.log, ["subject:sess_b", "as:customer", "as:door_token"]);
  fake.log.length = 0;
  advance(5 * 60_000);
  await kit.credentialFor(A);
  assert.deepEqual(fake.log, MINT_A);
  fake.done();
});

test("concurrent calls under one key share one mint", async () => {
  const { kit, fake } = setup();
  const [x, y] = await Promise.all([kit.credentialFor(A), kit.credentialFor({ key: "sess_a" })]);
  assert.equal(x.accessToken, y.accessToken);
  assert.deepEqual(fake.log, MINT_A);
  fake.done();
});

test("CustomerRef.key separates customers' cached credentials", async () => {
  const { kit, fake } = setup();
  const a = await kit.credentialFor(A);
  const b = await kit.credentialFor(B);
  assert.notEqual(a.accessToken, b.accessToken);
  // Each customer's hop 2 presented that customer's own subject token.
  const subjects = fake.requests.filter((r) => r.step === "customer").map((r) => r.form?.subject_token);
  assert.equal(subjects.length, 2);
  assert.match(subjects[0] ?? "", /^idp-sess_a-/);
  assert.match(subjects[1] ?? "", /^idp-sess_b-/);
  // A forget or refusal under one key leaves the other's credential.
  kit.forget(A);
  assert.equal((await kit.credentialFor(B)).accessToken, b.accessToken);
  assert.notEqual((await kit.credentialFor(A)).accessToken, a.accessToken);
  fake.done();
});

test("eviction is by insertion order at maxCached, and a read does not move an entry", async () => {
  const { kit, fake } = setup({ maxCached: 2 });
  const a = await kit.credentialFor(A);
  const b = await kit.credentialFor(B);
  assert.equal((await kit.credentialFor(A)).accessToken, a.accessToken, "a read of the earliest entry");
  await kit.credentialFor({ key: "sess_c" }); // evicts sess_a, the earliest inserted, despite the read
  fake.log.length = 0;
  assert.equal((await kit.credentialFor(B)).accessToken, b.accessToken, "sess_b is kept");
  assert.deepEqual(fake.log, []);
  assert.notEqual((await kit.credentialFor(A)).accessToken, a.accessToken, "sess_a was evicted");
  assert.deepEqual(fake.log, ["subject:sess_a", "as:customer", "as:door_token"]);
  fake.done();
});

test("expired entries are swept before a live one is evicted", async () => {
  const { kit, fake, advance } = setup({ maxCached: 2 });
  // sess_b, the earliest inserted, is live; sess_a, inserted after it, has expired. Without the sweep, insertion
  // order would evict sess_b.
  const b = await kit.credentialFor(B);
  fake.ttl.door = 60; // sess_a's lasts one minute
  await kit.credentialFor(A);
  fake.ttl.door = 300;
  advance(60_000);
  await kit.credentialFor({ key: "sess_c" });
  fake.log.length = 0;
  assert.equal((await kit.credentialFor(B)).accessToken, b.accessToken);
  assert.deepEqual(fake.log, []);
  fake.done();
});

test("{fresh} mints all three hops, even with a cached backend session, and replaces the cache", async () => {
  const { kit, fake } = setup();
  const cached = await kit.credentialFor(A);
  const actors = () => fake.requests.filter((r) => r.step === "customer").map((r) => r.form?.actor_token);
  fake.log.length = 0;
  const fresh = await kit.credentialFor(A, { fresh: true });
  assert.notEqual(fresh.accessToken, cached.accessToken);
  assert.deepEqual(fake.log, MINT_A, "hop 1 is minted again although the cached one has minutes left");
  assert.notEqual(actors()[1], actors()[0], "the fresh hop 2 rides the fresh hop 1");
  fake.log.length = 0;
  // A poll (no fresh) uses the cache, which now holds the fresh credential.
  assert.equal((await kit.credentialFor(A)).accessToken, fresh.accessToken);
  assert.deepEqual(fake.log, []);
  // The fresh hop 1 replaced the cached one: another customer's mint uses it.
  await kit.credentialFor(B);
  assert.deepEqual(fake.log, ["subject:sess_b", "as:customer", "as:door_token"]);
  assert.equal(actors()[2], actors()[1]);
  // A refusal of the replaced credential never drops the fresh one.
  kit.forget(A, new OnBehalfError("door", 401, "invalid_token"), cached);
  assert.equal((await kit.credentialFor(A)).accessToken, fresh.accessToken);
  fake.done();
});

test("a fresh mint replaces a cached mint still in flight", async () => {
  const { kit, fake } = setup();
  const pending = kit.credentialFor(A);
  const fresh = await kit.credentialFor(A, { fresh: true });
  await pending;
  assert.equal((await kit.credentialFor(A)).accessToken, fresh.accessToken);
  fake.done();
});

test("forget(c) drops the credential, also one minted while in flight", async () => {
  const { kit, fake } = setup();
  const a = await kit.credentialFor(A);
  kit.forget(A);
  fake.log.length = 0;
  const again = await kit.credentialFor(A);
  assert.notEqual(again.accessToken, a.accessToken);
  assert.deepEqual(fake.log, ["subject:sess_a", "as:customer", "as:door_token"]);
  const pending = kit.credentialFor(B);
  kit.forget(B); // sign-out while the mint is in flight
  const b = await pending;
  assert.notEqual((await kit.credentialFor(B)).accessToken, b.accessToken, "the in-flight one was not cached");
  fake.done();
});

test("a refusal of an older credential never drops the newer one cached since", async () => {
  const { kit, advance, fake } = setup();
  const older = await kit.credentialFor(A);
  advance(5 * 60_000);
  const newer = await kit.credentialFor(A);
  const refused = new OnBehalfError("door", 401, "invalid_token");
  kit.forget(A, refused, older);
  assert.equal((await kit.credentialFor(A)).accessToken, newer.accessToken, "the newer one is kept");
  kit.forget(A, refused, newer);
  assert.notEqual((await kit.credentialFor(A)).accessToken, newer.accessToken, "the refused one is dropped");
  fake.done();
});

test("every attempt presents a fresh subject: the nonce retry at hop 2", async () => {
  const { kit, fake } = setup();
  fake.once("customer", { status: 400, headers: { "dpop-nonce": "as-n-1" }, body: { error: "use_dpop_nonce" } });
  await kit.credentialFor(A);
  const hop2 = fake.requests.filter((r) => r.step === "customer");
  assert.equal(hop2.length, 2);
  assert.notEqual(hop2[0]?.form?.subject_token, hop2[1]?.form?.subject_token, "the retry fetched a new subject");
  assert.equal(hop2[1]?.proof?.payload.nonce, "as-n-1");
  assert.deepEqual(fake.log.filter((l) => l.startsWith("subject:")).length, 2);
  fake.done();
});

test("every attempt presents a fresh assertion: the nonce retry at hop 1", async () => {
  const { kit, fake } = setup();
  fake.once("backend", { status: 400, headers: { "dpop-nonce": "as-n-1" }, body: { error: "use_dpop_nonce" } });
  await kit.credentialFor(A);
  assert.equal(fake.jtis.length, 2);
  assert.notEqual(fake.jtis[0], fake.jtis[1]);
  // The nonce is kept for every later proof to the authorization server.
  for (const r of fake.requests.slice(1)) assert.equal(r.proof?.payload.nonce, "as-n-1");
  fake.done();
});

test("the adopter's retry after a 5xx fetches a fresh subject and a fresh assertion", async () => {
  const { kit, fake } = setup();
  fake.once("backend", { status: 503, body: { error: "temporarily_unavailable" } });
  await assert.rejects(kit.credentialFor(A), (e: unknown) => e instanceof OnBehalfError && e.step === "backend");
  fake.once("customer", { status: 503, body: { error: "temporarily_unavailable" } });
  await assert.rejects(kit.credentialFor(A), (e: unknown) => e instanceof OnBehalfError && e.status === 503);
  fake.once("customer", { status: 500, body: { error: "server_error" } });
  await assert.rejects(kit.credentialFor(A));
  await kit.credentialFor(A);
  const subjects = fake.requests.filter((r) => r.step === "customer").map((r) => r.form?.subject_token);
  assert.equal(subjects.length, 3);
  assert.equal(new Set(subjects).size, 3, "no subject token is presented twice");
  assert.equal(new Set(fake.jtis).size, fake.jtis.length);
  // The 5xx at hop 2 kept the backend's session: one hop 1 after the first outage, none since.
  assert.equal(fake.log.filter((l) => l === "as:backend").length, 2);
  fake.done();
});

test("the customer exchange's actor_token_not_usable drops the backend's session", async () => {
  const { kit, fake } = setup();
  fake.once("customer", {
    status: 400,
    body: { error: "invalid_grant", error_description: "actor_token_not_usable" },
  });
  await assert.rejects(kit.credentialFor(A), (e: unknown) => classify(e).dropActor);
  fake.log.length = 0;
  await kit.credentialFor(A);
  assert.equal(fake.log[0], "as:backend");
  fake.done();
});

// No refusal but the one that names it drops the backend's session.
const NOT_THE_ACTOR: { at: Step; answer: Answer }[] = [
  { at: "customer", answer: { status: 400, body: { error: "invalid_grant" } } },
  { at: "customer", answer: { status: 400, body: { error: "invalid_grant", error_description: "other" } } },
  { at: "customer", answer: { status: 403, body: { error: "access_denied" } } },
  { at: "customer", answer: { status: 400, body: { error: "invalid_dpop_proof" } } },
  { at: "customer", answer: { status: 503, body: { error: "temporarily_unavailable" } } },
  { at: "door_token", answer: { status: 400, body: { error: "invalid_grant" } } },
  { at: "door_token", answer: { status: 400, body: { error: "invalid_scope" } } },
  { at: "door_token", answer: { status: 500, body: { error: "server_error" } } },
  { at: "subject", answer: { status: 500 } },
];
for (const r of NOT_THE_ACTOR) {
  test(`a refusal that does not name the backend's session keeps it: ${r.at} ${JSON.stringify(r.answer)}`, async () => {
    const { kit, fake } = setup();
    await kit.credentialFor(B);
    fake.once(r.at, r.answer);
    await assert.rejects(kit.credentialFor(A), (e: unknown) => !classify(e).dropActor);
    fake.log.length = 0;
    await kit.credentialFor(A);
    assert.ok(!fake.log.includes("as:backend"), fake.log.join(" "));
    fake.done();
  });
}

test("the settled disposition rows", () => {
  const e = (step: OnBehalfError["step"], status: number, code: string | null, description?: string) =>
    classify(new OnBehalfError(step, status, code, { description: description ?? null }));
  const drop = { dropActor: false, dropCustomer: true, reason: "unavailable" };
  const keep = { dropActor: false, dropCustomer: false, reason: "unavailable" };
  const defect = { dropActor: false, dropCustomer: false, reason: "kit_defect", code: "invalid_dpop_proof" };
  assert.deepEqual(e("customer", 400, "invalid_grant", "actor_token_not_usable"), { ...drop, dropActor: true });
  assert.deepEqual(e("door_token", 400, "invalid_grant"), drop);
  assert.deepEqual(e("door", 401, "invalid_token"), drop);
  assert.deepEqual(e("customer", 403, "access_denied"), drop);
  for (const step of ["subject", "backend", "customer", "door_token", "door"] as const) {
    assert.deepEqual(e(step, 503, "temporarily_unavailable"), keep, `${step} 503`);
    assert.deepEqual(e(step, 400, "invalid_dpop_proof"), defect, `${step} invalid_dpop_proof`);
  }
  assert.deepEqual(e("door", 401, "invalid_dpop_proof"), defect);
  assert.equal(new OnBehalfError("customer", 400, "invalid_dpop_proof").reason, "kit_defect");
  assert.deepEqual(e("door", 403, "insufficient_scope"), keep);
  assert.deepEqual(e("door", 429, null), keep);
  assert.deepEqual(e("backend", 400, "invalid_grant"), keep);
  assert.deepEqual(classify(new Error("connect ECONNRESET")), keep);
  assert.equal(new OnBehalfError("door", 401, "invalid_token").reason, "unavailable");
});

test("a sign-out during a fresh mint leaves it uncached", async () => {
  const { kit, fake } = setup();
  const pending = kit.credentialFor(A, { fresh: true });
  kit.forget(A); // sign-out while the fresh mint is in flight
  const a = await pending;
  fake.log.length = 0;
  assert.notEqual((await kit.credentialFor(A)).accessToken, a.accessToken, "it was not cached");
  assert.deepEqual(fake.log, ["subject:sess_a", "as:customer", "as:door_token"]);
  fake.done();
});

for (const expires_in of [0, -1]) {
  test(`a grant answer with expires_in ${expires_in} is refused, not cached`, async () => {
    const { kit, fake } = setup();
    fake.ttl.door = expires_in;
    await assert.rejects(kit.credentialFor(A), (e: unknown) => e instanceof OnBehalfError && e.step === "door_token");
    fake.ttl.door = 300;
    fake.log.length = 0;
    await kit.credentialFor(A);
    assert.deepEqual(hops(fake.log), ["subject:sess_a", "as:customer", "as:door_token"]);
    fake.done();
  });
}

test("a lifetime longer than five minutes is not believed", async () => {
  const { kit, fake, advance } = setup();
  fake.ttl = { backend: 86_400, customer: 86_400, door: 86_400 };
  await kit.credentialFor(A);
  fake.log.length = 0;
  advance(5 * 60_000);
  await kit.credentialFor(A);
  assert.deepEqual(fake.log, MINT_A);
  fake.done();
});

test("a door token issued as anything but DPoP is refused, not cached", async () => {
  const { kit, fake } = setup();
  fake.doorTokenType = "Bearer";
  await assert.rejects(kit.credentialFor(A), (e: unknown) => e instanceof OnBehalfError && e.step === "door_token");
  fake.doorTokenType = "DPoP";
  fake.log.length = 0;
  await kit.credentialFor(A);
  assert.deepEqual(hops(fake.log), ["subject:sess_a", "as:customer", "as:door_token"]);
  fake.done();
});

test("a failing subject provider is step subject and drops nothing", async () => {
  const { kit, fake } = setup();
  fake.once("subject", { status: 500 });
  await assert.rejects(kit.credentialFor(A), (e: unknown) => {
    assert.ok(e instanceof OnBehalfError);
    assert.equal(e.step, "subject");
    assert.deepEqual(classify(e), { dropActor: false, dropCustomer: false, reason: "unavailable" });
    return true;
  });
  fake.done();
});

test("the Clerk adapter mints the subject from the session's template", async () => {
  let fake!: ReturnType<typeof setup>["fake"];
  const { kit, fake: f } = setup({
    subjectToken: (c) =>
      clerkSubjectTokens({ secretKey: "sk_test_fake", template: "varketa", apiUrl: CLERK_API, fetch: f0 })(c),
  });
  fake = f;
  function f0(...args: Parameters<typeof fake.fetch>) {
    return fake.fetch(...args);
  }
  await kit.credentialFor(A);
  assert.deepEqual(fake.log, ["as:backend", "clerk:sess_a", "as:customer", "as:door_token"]);
  const hop2 = fake.requests.find((r) => r.step === "customer");
  assert.match(hop2?.form?.subject_token ?? "", /^clerk-sess_a-/);
  fake.done();
});

test("a network error or a timeout at any hop is an OnBehalfError, status 0, and drops nothing", async () => {
  for (const at of ["backend", "customer", "door_token"] as const) {
    let fail = true;
    const { kit, fake } = setup({
      fetch: (url, init) => {
        const step = url.endsWith("/oauth/token")
          ? "door_token"
          : new URLSearchParams(init.body ?? "").has("actor_token")
            ? "customer"
            : "backend";
        if (step === at && fail) {
          fail = false;
          return Promise.reject(new TypeError("fetch failed"));
        }
        return fake.fetch(url, init);
      },
    });
    await assert.rejects(kit.credentialFor(A), (e: unknown) => {
      assert.ok(e instanceof OnBehalfError, `${at}: ${String(e)}`);
      assert.deepEqual([e.step, e.status, e.code], [at, 0, null]);
      assert.ok(e.cause instanceof TypeError);
      assert.deepEqual(classify(e), { dropActor: false, dropCustomer: false, reason: "unavailable" });
      return true;
    });
    fake.log.length = 0;
    await kit.credentialFor(A);
    // The backend's session minted before the failure is kept.
    assert.deepEqual(fake.log, at === "backend" ? MINT_A : ["subject:sess_a", "as:customer", "as:door_token"], at);
    fake.done();
  }
});

test("a failing signer is step backend, status 0", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
  const kms = new Error("kms unavailable");
  const backend = new BackendIdentity({
    issuer: "https://backend.adopter.example",
    subject: "backend",
    audience: "varketa-aud",
    signer: { publicJwk: jwk as EcJwk, sign: () => Promise.reject(kms) },
  });
  const { kit, fake } = setup({ backend });
  await assert.rejects(kit.credentialFor(A), (e: unknown) => {
    assert.ok(e instanceof OnBehalfError);
    assert.deepEqual([e.step, e.status, e.cause], ["backend", 0, kms]);
    return true;
  });
  assert.deepEqual(fake.log, []);
  fake.done();
});

test("the Clerk adapter's refusal is step subject with Clerk's status", async () => {
  const provider = clerkSubjectTokens({
    secretKey: "sk_test_fake",
    template: "varketa",
    apiUrl: CLERK_API,
    fetch: async () => ({ status: 404, headers: { get: () => null }, text: async () => '{"errors":[]}' }),
  });
  await assert.rejects(provider(A), (e: unknown) => {
    assert.ok(e instanceof OnBehalfError);
    assert.deepEqual([e.step, e.status], ["subject", 404]);
    return true;
  });
});

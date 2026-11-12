import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { DpopFetch } from "../src/index.ts";
import { MCP } from "./fake/varketa.ts";
import { hops, setup } from "./fake/setup.ts";

const A = { key: "sess_a" };
const ath = (t: string) => createHash("sha256").update(t).digest("base64url");
const rpc = (method: string) => ({
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer not-this-one" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method }),
});

// The official SDK's FetchLike (client/streamableHttp.d.ts at 1.31.0), restated: no SDK import.
type SdkFetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>;
const asSdk = (f: DpopFetch): SdkFetchLike => f;

test("each request carries the door token and a fresh proof with ath; the caller's own is replaced", async () => {
  const { kit, fake } = setup();
  const f = asSdk(await kit.fetchFor(A));
  const res = await f(MCP, rpc("initialize"));
  assert.equal(res.status, 200);
  const door = fake.requests.filter((r) => r.step === "door");
  assert.equal(door.length, 1);
  const token = /^DPoP (.+)$/.exec(door[0]?.headers.authorization ?? "")?.[1] ?? "";
  assert.match(token, /^door_token-/);
  assert.equal(door[0]?.proof?.payload.ath, ath(token));
  await f(new URL(MCP), rpc("tools/list"));
  const jtis = fake.requests.filter((r) => r.step === "door").map((r) => r.proof?.payload.jti);
  assert.notEqual(jtis[0], jtis[1], "a fresh proof per request");
  fake.done();
});

test("a GET and a DELETE carry a proof whose htm and htu match, with ath", async () => {
  const { kit, fake } = setup();
  const f = await kit.fetchFor(A);
  assert.equal((await f(MCP, { method: "GET", headers: { accept: "text/event-stream" } })).status, 200);
  assert.equal((await f(MCP, { method: "DELETE", headers: { "mcp-session-id": "s-1" } })).status, 204);
  const door = fake.requests.filter((r) => r.step === "door");
  assert.deepEqual(
    door.map((r) => [r.method, r.proof?.payload.htm, r.proof?.payload.htu]),
    [
      ["GET", "GET", MCP],
      ["DELETE", "DELETE", MCP],
    ],
  );
  for (const r of door) {
    const token = /^DPoP (.+)$/.exec(r.headers.authorization ?? "")?.[1] ?? "";
    assert.equal(r.proof?.payload.ath, ath(token));
  }
  assert.equal(door[1]?.headers["mcp-session-id"], "s-1", "the caller's other headers pass through");
  fake.done();
});

test("any URL but mcpResource is refused before anything is sent", async () => {
  const { kit, fake } = setup();
  const f = await kit.fetchFor(A);
  const sent = fake.requests.length;
  for (const url of [
    "https://evil.example/mcp",
    "https://tenant.varketa.example/mcp/other",
    "https://tenant.varketa.example/mcp?x=1",
    "http://tenant.varketa.example/mcp",
    "https://tenant.varketa.example:8443/mcp",
  ]) {
    await assert.rejects(f(url, rpc("initialize")), /mcpResource only/, url);
  }
  assert.equal(fake.requests.length, sent);
  const cred = await kit.credentialFor(A);
  assert.throws(() => cred.proof("POST", "https://evil.example/mcp"), /mcpResource only/);
  fake.done();
});

test("the door's nonce challenge is answered once, and the nonce kept", async () => {
  const { kit, fake } = setup();
  fake.once("door", {
    status: 401,
    headers: { "dpop-nonce": "n-1", "www-authenticate": 'DPoP error="use_dpop_nonce"' },
  });
  const f = await kit.fetchFor(A);
  assert.equal((await f(MCP, rpc("initialize"))).status, 200);
  await f(MCP, rpc("tools/list"));
  const nonces = fake.requests.filter((r) => r.step === "door").map((r) => r.proof?.payload.nonce);
  assert.deepEqual(nonces, [undefined, "n-1", "n-1"]);
  fake.log.length = 0;
  assert.equal((await kit.credentialFor(A)).accessToken.length > 0, true);
  assert.deepEqual(fake.log, [], "the nonce challenge dropped nothing");
  fake.done();
});

test("a nonce challenge the fetch cannot answer drops nothing", async () => {
  const { kit, fake } = setup();
  const f = await kit.fetchFor(A);
  const challenge = {
    status: 401,
    headers: { "dpop-nonce": "n-1", "www-authenticate": 'DPoP error="use_dpop_nonce"' },
  };
  // A stream body cannot be sent twice, so the challenge comes back to the caller.
  fake.once("door", challenge);
  const body = new Blob(["{}"]).stream();
  assert.equal((await f(MCP, { method: "POST", body, duplex: "half" } as RequestInit)).status, 401);
  // A nonce that rotates again answers the retry with another challenge.
  fake.once("door", challenge);
  fake.once("door", { ...challenge, headers: { ...challenge.headers, "dpop-nonce": "n-2" } });
  assert.equal((await f(MCP, rpc("tools/list"))).status, 401);
  fake.log.length = 0;
  assert.equal((await f(MCP, rpc("tools/list"))).status, 200);
  assert.deepEqual(hops(fake.log), [], "the credential was kept");
  fake.done();
});

test("a door 401 drops the customer's credential, and only that one", async () => {
  const { kit, fake } = setup();
  const other = await kit.credentialFor({ key: "sess_b" });
  const f = await kit.fetchFor(A);
  fake.once("door", { status: 401, headers: { "www-authenticate": 'DPoP error="invalid_token"' } });
  assert.equal((await f(MCP, rpc("tools/list"))).status, 401);
  fake.log.length = 0;
  assert.equal((await f(MCP, rpc("tools/list"))).status, 200);
  assert.deepEqual(hops(fake.log), ["subject:sess_a", "as:customer", "as:door_token"], "re-minted, actor kept");
  assert.equal((await kit.credentialFor({ key: "sess_b" })).accessToken, other.accessToken);
  fake.done();
});

test("a door 403, 429, 503 or an invalid_dpop_proof 401 drops nothing", async () => {
  const { kit, fake } = setup();
  const f = await kit.fetchFor(A);
  const answers = [
    { status: 403, headers: { "www-authenticate": 'DPoP error="insufficient_scope"' } },
    { status: 429 },
    { status: 503 },
    { status: 401, headers: { "www-authenticate": 'DPoP error="invalid_dpop_proof"' } },
  ];
  for (const a of answers) {
    fake.once("door", a);
    assert.equal((await f(MCP, rpc("tools/list"))).status, a.status);
  }
  fake.log.length = 0;
  await f(MCP, rpc("tools/list"));
  assert.deepEqual(hops(fake.log), []);
  fake.done();
});

test("a fresh fetch mints all three hops, and its credential replaces the cached one", async () => {
  const { kit, fake } = setup();
  const cached = await kit.credentialFor(A);
  fake.log.length = 0;
  const f = await kit.fetchFor(A, { fresh: true });
  assert.deepEqual(fake.log, ["as:backend", "subject:sess_a", "as:customer", "as:door_token"]);
  await f(MCP, rpc("tools/call"));
  const token = /^DPoP (.+)$/.exec(fake.requests.at(-1)?.headers.authorization ?? "")?.[1];
  assert.notEqual(token, cached.accessToken);
  fake.log.length = 0;
  assert.equal((await kit.credentialFor(A)).accessToken, token, "the fresh one is now the cached one");
  assert.deepEqual(fake.log, []);
  fake.done();
});

test("a fresh fetch whose credential expires mid-session re-mints, with a fresh subject", async () => {
  const { kit, fake, advance } = setup();
  const f = await kit.fetchFor(A, { fresh: true });
  await f(MCP, rpc("tools/call"));
  const first = fake.requests.at(-1)?.headers.authorization;
  advance(2 * 60_000);
  await f(MCP, rpc("tasks/get"));
  assert.equal(fake.requests.at(-1)?.headers.authorization, first, "still live: the same credential");
  fake.log.length = 0;
  advance(3 * 60_000); // past its five minutes
  await f(MCP, rpc("tasks/get"));
  assert.deepEqual(hops(fake.log), ["as:backend", "subject:sess_a", "as:customer", "as:door_token"]);
  assert.notEqual(fake.requests.at(-1)?.headers.authorization, first);
  // The fake refuses any subject token presented twice; every hop-2 subject differs.
  const subjects = fake.requests.filter((r) => r.step === "customer").map((r) => r.form?.subject_token);
  assert.equal(new Set(subjects).size, subjects.length);
  fake.done();
});

test("a fresh fetch's credential refused by the door is replaced on the next request", async () => {
  const { kit, fake } = setup();
  const f = await kit.fetchFor(A, { fresh: true });
  // A kit defect drops nothing: the same credential is used again.
  fake.once("door", { status: 401, headers: { "www-authenticate": 'DPoP error="invalid_dpop_proof"' } });
  assert.equal((await f(MCP, rpc("tools/call"))).status, 401);
  fake.once("door", { status: 401, headers: { "www-authenticate": 'DPoP error="invalid_token"' } });
  fake.log.length = 0;
  assert.equal((await f(MCP, rpc("tools/call"))).status, 401);
  assert.deepEqual(hops(fake.log), []);
  fake.log.length = 0;
  assert.equal((await f(MCP, rpc("tools/call"))).status, 200);
  assert.deepEqual(hops(fake.log), ["as:backend", "subject:sess_a", "as:customer", "as:door_token"]);
  // The refused one was also dropped from the cache: an ordinary call gets the replacement.
  const now = /^DPoP (.+)$/.exec(fake.requests.at(-1)?.headers.authorization ?? "")?.[1];
  fake.log.length = 0;
  assert.equal((await kit.credentialFor(A)).accessToken, now);
  assert.deepEqual(fake.log, []);
  fake.done();
});

test("a sign-out during a fresh fetch's mint ends that credential", async () => {
  const { kit, fake } = setup();
  const pending = kit.fetchFor(A, { fresh: true });
  kit.forget(A); // sign-out while the fetch's first fresh mint is in flight
  const f = await pending;
  fake.log.length = 0;
  await f(MCP, rpc("tools/call"));
  assert.deepEqual(hops(fake.log), ["as:backend", "subject:sess_a", "as:customer", "as:door_token"]);
  fake.done();
});

test("concurrent requests on a fresh fetch share one re-mint", async () => {
  const { kit, fake, advance } = setup();
  const f = await kit.fetchFor(A, { fresh: true });
  advance(5 * 60_000);
  fake.log.length = 0;
  await Promise.all([f(MCP, rpc("tools/call")), f(MCP, { method: "GET" }), f(MCP, rpc("tasks/get"))]);
  assert.deepEqual(hops(fake.log), ["as:backend", "subject:sess_a", "as:customer", "as:door_token"]);
  fake.done();
});

test("a sign-out ends a fresh fetch's own credential", async () => {
  const { kit, fake } = setup();
  const f = await kit.fetchFor(A, { fresh: true });
  await f(MCP, rpc("tools/call"));
  const first = fake.requests.at(-1)?.headers.authorization;
  kit.forget(A);
  fake.log.length = 0;
  await f(MCP, rpc("tools/call"));
  assert.deepEqual(hops(fake.log), ["as:backend", "subject:sess_a", "as:customer", "as:door_token"]);
  assert.notEqual(fake.requests.at(-1)?.headers.authorization, first);
  fake.done();
});

test("fetchFor surfaces a refused mint itself", async () => {
  const { kit, fake } = setup();
  fake.once("door_token", { status: 400, body: { error: "invalid_scope" } });
  await assert.rejects(kit.fetchFor(A), { name: "OnBehalfError", step: "door_token" });
  assert.equal(fake.requests.filter((r) => r.step === "door").length, 0);
  fake.done();
});

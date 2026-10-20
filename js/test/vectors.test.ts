import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { join } from "node:path";
import { Verifier, InMemoryReplayStore, VerificationError, SUPPORTED_VERSIONS, type FetchedDocument } from "../src/index.ts";

const vectors = join(import.meta.dirname, "..", "..", "vectors");
// The current set, which the tests below the vectors also read.
const dir = join(vectors, "v4");
const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
// Each accepted claim-set version's set, and the cases a later version supersedes, each with its reason. A superseded
// case is not skipped: its refusal no longer holds, so its first step must now be accepted.
const SETS: { version: string; superseded: Record<string, string> }[] = [
  { version: "v4", superseded: {} },
  // v3's unknown-ver presents ver 4, unknown when v3 was cut and accepted since; v4's unknown-ver presents ver 5.
  { version: "v3", superseded: { "unknown-ver": "ver 4 is a known claim set since v4" } },
];

interface Step {
  now: number;
  request: { method: string; url: string; body_b64url: string };
  assertion: string;
  expect: { accept: boolean; code?: string; identity?: Record<string, unknown>; jwks_fetches?: number };
}
interface Case { name: string; fetches: Record<string, { status: number; cache_control?: string; body?: unknown }[]>; steps: Step[] }

function harness(c: Case, m = manifest) {
  const counts = new Map<string, number>();
  let now = 0;
  const v = new Verifier({
    ...m.config,
    replayStore: new InMemoryReplayStore({ singleInstance: true }),
    clock: () => now,
    fetchDocument: async (url: string): Promise<FetchedDocument> => {
      const rs = c.fetches[url] ?? [];
      const i = counts.get(url) ?? 0;
      counts.set(url, i + 1);
      const r = rs[Math.min(i, rs.length - 1)];
      if (!r) throw new Error(`no scripted response for ${url}`);
      return { status: r.status, cacheControl: r.cache_control ?? null, body: r.body === undefined ? "" : JSON.stringify(r.body) };
    },
  });
  return { v, counts, setNow: (t: number) => { now = t; } };
}

test("the vector sets are the accepted claim sets, and package.json names them", () => {
  assert.deepEqual(SETS.map((s) => Number(s.version.slice(1))).sort(), [...SUPPORTED_VERSIONS].sort());
  const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"));
  assert.deepEqual(pkg.varketa, { claimSetVersions: [...SUPPORTED_VERSIONS], vectors: manifest.version });
});

for (const set of SETS) {
  const setDir = join(vectors, set.version);
  const setManifest = JSON.parse(readFileSync(join(setDir, "manifest.json"), "utf8"));

  test(`${set.version}: the case set is the manifest's`, () => {
    const files = readdirSync(join(setDir, "cases")).map((f) => f.replace(/\.json$/, "")).sort();
    assert.deepEqual(files, [...setManifest.cases].sort());
    assert.ok(setManifest.cases.length > 0, "an empty set proves nothing");
    assert.equal(`v${setManifest.claim_set_ver}`, set.version);
    for (const name of Object.keys(set.superseded)) assert.ok(setManifest.cases.includes(name), `${name} is not a ${set.version} case`);
  });

  for (const name of setManifest.cases as string[]) {
    const superseded = set.superseded[name];
    test(`${set.version}: vector ${name}${superseded ? ` (superseded: ${superseded})` : ""}`, async () => {
      const c: Case = JSON.parse(readFileSync(join(setDir, "cases", `${name}.json`), "utf8"));
      const h = harness(c, setManifest);
      if (superseded) {
        const s = c.steps[0];
        h.setNow(s.now);
        await h.v.verify({ method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion });
        return;
      }
      for (const [i, s] of c.steps.entries()) {
        h.setNow(s.now);
        const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion };
        let code = "";
        let identity: unknown;
        try {
          identity = await h.v.verify(req);
        } catch (e) {
          if (!(e instanceof VerificationError)) throw e;
          code = e.code;
        }
        if (s.expect.accept) {
          assert.equal(code, "", `step ${i} refused`);
          assert.deepEqual(identity, s.expect.identity, `step ${i} identity`);
        } else {
          assert.equal(code, s.expect.code, `step ${i} code`);
        }
        if (s.expect.jwks_fetches) {
          const jwks = `${setManifest.config.issuer}/.well-known/varketa-acting-principal/jwks.json`;
          assert.equal(h.counts.get(jwks), s.expect.jwks_fetches, `step ${i} key-set fetches`);
        }
      }
    });
  }
}

test("with an atomic store, of two concurrent copies of one assertion exactly one is accepted", async () => {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const h = harness(c);
  const s = c.steps[0];
  h.setNow(s.now);
  const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion };
  const results = await Promise.allSettled([h.v.verify(req), h.v.verify(req)]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  const refused = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
  assert.equal((refused.reason as VerificationError).code, "replay");
  for (const n of h.counts.values()) assert.equal(n, 1, "concurrent cold requests share discovery");
});

test("the verifier refuses to start without its issuer, adopter, audience or replay store", () => {
  const store = new InMemoryReplayStore({ singleInstance: true });
  const ok = { ...manifest.config, replayStore: store };
  assert.doesNotThrow(() => new Verifier(ok));
  for (const k of ["issuer", "adopter", "audience", "replayStore"]) {
    assert.throws(() => new Verifier({ ...ok, [k]: k === "replayStore" ? undefined : "" }), new RegExp(k));
  }
  assert.throws(() => new InMemoryReplayStore({} as never), /single instance/);
  for (const issuer of ["http://api.varketa.ai", "https://api.varketa.ai/", "https://api.varketa.ai/x", "file:///etc/x"]) {
    assert.throws(() => new Verifier({ ...ok, issuer }), /https:\/\/ origin/, issuer);
  }
  for (const audience of ["http://api.example", "https://api.example/", "https://api.example/x", "https://user:pass@api.example", "https://api.example:99999"]) {
    assert.throws(() => new Verifier({ ...ok, audience }), /audience/);
  }
});

test("the replay record lives through the last accepted second, a whole number of seconds", async () => {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "exp-within-skew.json"), "utf8"));
  const calls: number[] = [];
  const counts = new Map<string, number>();
  const s = c.steps[0];
  const v = new Verifier({
    ...manifest.config,
    replayStore: { async setIfAbsent(_k: string, ttl: number) { calls.push(ttl); return true; } },
    clock: () => s.now,
    fetchDocument: async (url: string) => {
      const i = counts.get(url) ?? 0;
      counts.set(url, i + 1);
      const r = c.fetches[url][Math.min(i, c.fetches[url].length - 1)];
      return { status: r.status, cacheControl: r.cache_control ?? null, body: JSON.stringify(r.body) };
    },
  });
  await v.verify({ method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion });
  assert.deepEqual(calls, [1]);
});

test("the in-memory replay store releases a key at its exclusive TTL boundary", async () => {
  const store = new InMemoryReplayStore({ singleInstance: true });
  assert.equal(await store.setIfAbsent("key", 2, 100), true);
  assert.equal(await store.setIfAbsent("key", 2, 101), false);
  assert.equal(await store.setIfAbsent("key", 2, 102), true);
});

for (const expired of ["metadata", "keys"] as const) {
  test(`expired ${expired} must be refreshed even while the other document is fresh`, async () => {
    const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
    const url = manifest.config.issuer + (expired === "metadata" ? "/.well-known/varketa-acting-principal" : "/.well-known/varketa-acting-principal/jwks.json");
    c.fetches[url][0].cache_control = "max-age=1";
    c.fetches[url].push({ status: 503 });
    const h = harness(c), s = c.steps[0];
    const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion };
    h.setNow(s.now);
    await h.v.verify(req);
    // A distinct signed jti, at max-age rather than one second after it.
    const previous: Case = JSON.parse(readFileSync(join(dir, "cases", "previous-key.json"), "utf8"));
    h.setNow(s.now + 1);
    await assert.rejects(h.v.verify({ ...req, assertion: previous.steps[0].assertion }), (e) => e instanceof VerificationError && e.code === "jwks_unavailable");
    assert.equal(h.counts.get(url), 2);
  });
}

test("a JWS segment cannot hide a trailing newline or invalid base64url length", async () => {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const s = c.steps[0], parts = s.assertion.split(".");
  for (const signature of [parts[2] + "\n", "A"]) {
    const h = harness(c);
    h.setNow(s.now);
    await assert.rejects(h.v.verify({ method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: `${parts[0]}.${parts[1]}.${signature}` }),
      (e) => e instanceof VerificationError && e.code === "malformed");
  }
});

test("malformed UTF-8 in a header cannot be repaired into JSON", async () => {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const h = harness(c);
  const header = Buffer.concat([Buffer.from('{"ignored":"'), Buffer.from([0xff]), Buffer.from('","typ":"varketa-acting-principal+jwt","alg":"none"}')]).toString("base64url");
  await assert.rejects(h.v.verify({ method: "GET", url: "https://example.invalid", body: "", assertion: `${header}.e30.AAAA` }),
    (e) => e instanceof VerificationError && e.code === "malformed");
});

test("discovery that expires during its fetch is unavailable", async () => {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const s = c.steps[0];
  let now = s.now;
  const v = new Verifier({ ...manifest.config, clock: () => now,
    replayStore: new InMemoryReplayStore({ singleInstance: true }),
    fetchDocument: async (url) => {
      const r = c.fetches[url][0];
      if (url.endsWith("jwks.json")) now += 2;
      return { status: r.status, cacheControl: "max-age=1", body: JSON.stringify(r.body) };
    } });
  await assert.rejects(v.verify({ method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion }),
    (e) => e instanceof VerificationError && e.code === "jwks_unavailable");
});

test("the default fetch refuses invalid UTF-8 and oversized documents, then recovers", async () => {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const s = c.steps[0], originalFetch = globalThis.fetch;
  const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: s.assertion };
  const metadataUrl = manifest.config.issuer + "/.well-known/varketa-acting-principal";
  const malformedMetadata = Buffer.concat([Buffer.from('{"ignored":"'), Buffer.from([0xff]),
    Buffer.from('",' + JSON.stringify(c.fetches[metadataUrl][0].body).slice(1))]);
  try {
    for (const invalid of [malformedMetadata, new Uint8Array(65537)]) {
      let fail = true;
      globalThis.fetch = async (url, options) => {
        assert.equal(options?.redirect, "error");
        assert.ok(options?.signal);
        const r = c.fetches[String(url)][0];
        return new Response(fail && String(url) === metadataUrl ? invalid : JSON.stringify(r.body),
          { status: 200, headers: { "cache-control": "max-age=300" } });
      };
      const v = new Verifier({ ...manifest.config, clock: () => s.now, replayStore: new InMemoryReplayStore({ singleInstance: true }) });
      await assert.rejects(v.verify(req), (e) => e instanceof VerificationError && e.code === "jwks_unavailable");
      fail = false;
      assert.equal((await v.verify(req)).tenant, s.expect.identity?.tenant);
    }
  } finally { globalThis.fetch = originalFetch; }
});

const jwksUrl = `${manifest.config.issuer}/.well-known/varketa-acting-principal/jwks.json`;

// A throwaway Ed25519 key under kid: its JWK, and an assertion of claims it signs.
function signer(kid: string) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  return {
    jwk: { ...publicKey.export({ format: "jwk" }), kid },
    sign(claims: unknown): string {
      const signingInput = `${enc({ typ: "varketa-acting-principal+jwt", alg: "EdDSA", kid })}.${enc(claims)}`;
      return `${signingInput}.${sign(null, Buffer.from(signingInput), privateKey).toString("base64url")}`;
    },
  };
}

// good's first step, its claims changed by change and signed again under a key the case's key set then carries.
async function resigned(change: (claims: Record<string, unknown>) => void): Promise<{ code: string; identity?: Record<string, unknown> }> {
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const s = c.steps[0];
  const claims = JSON.parse(Buffer.from(s.assertion.split(".")[1], "base64url").toString("utf8"));
  change(claims);
  const k = signer("test");
  (c.fetches[jwksUrl][0].body as { keys: unknown[] }).keys = [k.jwk];
  const h = harness(c);
  h.setNow(s.now);
  try {
    const identity = await h.v.verify({ method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url"), assertion: k.sign(claims) });
    return { code: "", identity: identity as unknown as Record<string, unknown> };
  } catch (e) {
    if (!(e instanceof VerificationError)) throw e;
    return { code: e.code };
  }
}

test("a present sub_id is exactly iss_sub", async () => {
  // Shapes no vector carries: a fourth member, null, an array, a non-string subject. And one sub_id on ver 3, which is
  // judged as on ver 4.
  const good = { format: "iss_sub", iss: "https://idp.adopter.example", sub: "user-8812" };
  const cases: [unknown, number, string][] = [
    [{ ...good, email: "user@adopter.example" }, 4, "malformed"], [null, 4, "malformed"], [[good], 4, "malformed"],
    [{ ...good, sub: 8812 }, 4, "malformed"], [{ ...good, iss: "" }, 3, "malformed"], [good, 3, ""],
  ];
  for (const [subId, ver, want] of cases) {
    const got = await resigned((c) => { c.sub_id = subId; c.ver = ver; });
    assert.equal(got.code, want, JSON.stringify({ subId, ver }));
    if (!want) assert.deepEqual(got.identity?.sub_id, good);
  }
});

test("JSON nested past the parser's limit is malformed", async () => {
  const h = harness({ name: "", fetches: {}, steps: [] });
  const head = Buffer.from("[".repeat(100000)).toString("base64url");
  await assert.rejects(h.v.verify({ method: "GET", url: "https://x", body: "", assertion: `${head}.e30.AAAA` }),
    (e) => e instanceof VerificationError && e.code === "malformed");
});

test("a number past the safe integers is absent", async () => {
  // As in the Python verifier: 2^60 is not a safe integer, so exp is absent and the refusal is expired.
  assert.equal((await resigned((c) => { c.exp = 2 ** 60; })).code, "expired");
});

test("a request for a rotated-in kid waits for the refetch another request already started", async () => {
  // The cached set lacks the new kid; the second fetch of the key set carries it. Two requests under the new kid, with
  // distinct jtis, arrive together: the first starts the refetch, the second must wait for it rather than refuse kid.
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const s = c.steps[0];
  const k = signer("rotated-in");
  const first = c.fetches[jwksUrl][0] as { status: number; cache_control?: string; body: { keys: unknown[] } };
  c.fetches[jwksUrl] = [first, { ...first, body: { keys: [...first.body.keys, k.jwk] } }];
  const h = harness(c);
  h.setNow(s.now);
  const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url") };
  await h.v.verify({ ...req, assertion: s.assertion });
  const claims = JSON.parse(Buffer.from(s.assertion.split(".")[1], "base64url").toString("utf8"));
  const ids = await Promise.all(["jti-a", "jti-b"].map((jti) => h.v.verify({ ...req, assertion: k.sign({ ...claims, jti }) })));
  assert.equal(ids.length, 2);
  assert.equal(h.counts.get(jwksUrl), 2, "one refetch, shared");
});

test("max-age follows HTTP's grammar: space or tab, ASCII digits", async () => {
  // A cacheable answer is fetched once for two assertions; an uncacheable one (max-age absent: 0) is fetched again.
  const previous: Case = JSON.parse(readFileSync(join(dir, "cases", "previous-key.json"), "utf8"));
  for (const [cacheControl, fetches] of [["no-cache, \tMAX-AGE=120", 1], ["max-age=\u0663\u0660\u0660", 2],
    ["no-cache,\x85max-age=120", 2], ["\xa0max-age=120", 2]] as const) {
    const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
    for (const rs of Object.values(c.fetches)) for (const r of rs) r.cache_control = cacheControl;
    const h = harness(c), s = c.steps[0];
    h.setNow(s.now);
    const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url") };
    await h.v.verify({ ...req, assertion: s.assertion });
    await h.v.verify({ ...req, assertion: previous.steps[0].assertion });
    assert.equal(h.counts.get(jwksUrl), fetches, JSON.stringify(cacheControl));
  }
});

test("an assertion refused for its sub_id leaves its jti unrecorded", async () => {
  // The sub_id check runs before the replay record: the same jti, well formed, is then accepted.
  const c: Case = JSON.parse(readFileSync(join(dir, "cases", "good.json"), "utf8"));
  const s = c.steps[0];
  const k = signer("test");
  (c.fetches[jwksUrl][0].body as { keys: unknown[] }).keys = [k.jwk];
  const h = harness(c);
  h.setNow(s.now);
  const claims = JSON.parse(Buffer.from(s.assertion.split(".")[1], "base64url").toString("utf8"));
  const req = { method: s.request.method, url: s.request.url, body: Buffer.from(s.request.body_b64url, "base64url") };
  await assert.rejects(h.v.verify({ ...req, assertion: k.sign({ ...claims, sub_id: { format: "email" } }) }),
    (e) => e instanceof VerificationError && e.code === "malformed");
  await h.v.verify({ ...req, assertion: k.sign(claims) });
});

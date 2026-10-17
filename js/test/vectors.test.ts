import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { Verifier, InMemoryReplayStore, VerificationError, type FetchedDocument } from "../src/index.ts";

const dir = join(import.meta.dirname, "..", "..", "vectors", "v3");
const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));

interface Step {
  now: number;
  request: { method: string; url: string; body_b64url: string };
  assertion: string;
  expect: { accept: boolean; code?: string; identity?: Record<string, unknown>; jwks_fetches?: number };
}
interface Case { name: string; fetches: Record<string, { status: number; cache_control?: string; body?: unknown }[]>; steps: Step[] }

function harness(c: Case) {
  const counts = new Map<string, number>();
  let now = 0;
  const v = new Verifier({
    ...manifest.config,
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

test("the case set is the manifest's", () => {
  const files = readdirSync(join(dir, "cases")).map((f) => f.replace(/\.json$/, "")).sort();
  assert.deepEqual(files, [...manifest.cases].sort());
});

for (const name of manifest.cases as string[]) {
  test(`vector ${name}`, async () => {
    const c: Case = JSON.parse(readFileSync(join(dir, "cases", `${name}.json`), "utf8"));
    const h = harness(c);
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
        const jwks = `${manifest.config.issuer}/.well-known/varketa-acting-principal/jwks.json`;
        assert.equal(h.counts.get(jwks), s.expect.jwks_fetches, `step ${i} key-set fetches`);
      }
    }
  });
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


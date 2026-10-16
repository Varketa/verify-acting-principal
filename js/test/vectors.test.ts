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


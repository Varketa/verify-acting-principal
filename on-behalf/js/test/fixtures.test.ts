// Runs every case of the fixture set package.json names: each step's expected requests (form fields, DPoP claims)
// in order, each answered with its recorded response, then the step's expected result.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { classify, OnBehalfError } from "../src/index.ts";
import { BACKEND, MCP, VARKETA, type Exchange } from "./fake/varketa.ts";
import { setup } from "./fake/setup.ts";

interface Step {
  do: "credential" | "fetch";
  customer: string;
  fresh?: boolean;
  advance_ms?: number;
  request?: { method: string; body?: string };
  exchanges: Exchange[];
  expect: {
    accept?: boolean;
    access_token?: string;
    status?: number;
    error?: { step: string; status: number; code: string | null; description: string | null };
    disposition?: { drop_actor: boolean; drop_customer: boolean };
  };
}

const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"));
const dir = join(import.meta.dirname, "..", "..", "fixtures", pkg.varketa.fixtures);
const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));

test("the fixture set's configuration is the fake's", () => {
  assert.equal(manifest.version, pkg.varketa.fixtures);
  assert.deepEqual(manifest.config, { varketa_origin: VARKETA, mcp_resource: MCP, backend: BACKEND });
  assert.ok(manifest.cases.length > 0);
});

for (const name of manifest.cases as string[]) {
  const c = JSON.parse(readFileSync(join(dir, "cases", `${name}.json`), "utf8")) as { steps: Step[] };
  test(`fixture ${name}`, async () => {
    const { kit, fake, advance } = setup();
    for (const [i, step] of c.steps.entries()) {
      const at = `${name} step ${i}`;
      if (step.advance_ms !== undefined) advance(step.advance_ms);
      fake.script(step.exchanges);
      const customer = { key: step.customer };
      const opts = step.fresh === true ? { fresh: true } : {};
      if (step.do === "credential") {
        let got: unknown;
        try {
          got = await kit.credentialFor(customer, opts);
        } catch (e) {
          got = e;
        }
        if (step.expect.accept === true) {
          assert.ok(!(got instanceof Error), `${at}: ${String(got)}`);
          assert.equal((got as { accessToken: string }).accessToken, step.expect.access_token, at);
        } else {
          assert.ok(got instanceof OnBehalfError, `${at}: ${String(got)}`);
          const { step: s, status, code, description } = got;
          assert.deepEqual({ step: s, status, code, description }, step.expect.error, at);
          const d = classify(got);
          assert.deepEqual(
            { drop_actor: d.dropActor, drop_customer: d.dropCustomer },
            step.expect.disposition,
            at,
          );
        }
      } else {
        const f = await kit.fetchFor(customer, opts);
        const res = await f(MCP, step.request);
        assert.equal(res.status, step.expect.status, at);
      }
      fake.done();
    }
  });
}

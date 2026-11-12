// One kit against one fake, with a clock the test moves.
import { generateKeyPairSync } from "node:crypto";
import { BackendIdentity, createOnBehalf, type OnBehalfOptions } from "../../src/index.ts";
import { BACKEND, FakeVarketa, MCP, VARKETA } from "./varketa.ts";

export const backendPem = () =>
  generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "pem", type: "pkcs8" }).toString();

export function setup(o: Partial<OnBehalfOptions> & { pem?: string } = {}) {
  const pem = o.pem ?? backendPem();
  const backend = o.backend ?? new BackendIdentity({ ...BACKEND, privateKeyPem: pem });
  const fake = new FakeVarketa(() => backend.jwks());
  let now = Date.parse("2026-11-12T12:00:00Z");
  const kit = createOnBehalf({
    varketaOrigin: VARKETA,
    mcpResource: MCP,
    backend,
    subjectToken: fake.subjectToken,
    fetch: fake.fetch,
    doorFetch: fake.doorFetch,
    now: () => now,
    ...o,
  });
  return { kit, fake, backend, pem, advance: (ms: number) => (now += ms) };
}

/** The log without door requests and the door's answers. */
export const hops = (log: string[]) => log.filter((l) => !l.startsWith("door:") && l !== "refused:door");

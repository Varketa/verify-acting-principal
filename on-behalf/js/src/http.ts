import { classify } from "./disposition.ts";

// The outbound HTTP shape the kit's calls to Varketa and the IdP use. The global fetch fits it; tests pass a fake.
export type HttpFetch = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text: () => Promise<string> }>;

/** Which call failed: the adopter's subject token, Varketa's exchange for the backend or for the customer,
 * Varketa's token endpoint for the door's token, or the door itself. */
export type OnBehalfStep = "subject" | "backend" | "customer" | "door_token" | "door";

/** What a failure means, as a code. The words a person reads are the adopter's. `kit_defect`: the server refused
 * the kit's own request (its code is in `Disposition.code`), so retrying unchanged will not help. */
export type OnBehalfReason = "unavailable" | "sign_in_first" | "not_set_up" | "not_admitted" | "kit_defect";

/** A failed on-behalf call: its step, its status (0 when no answer), and the OAuth `error` and
 * `error_description` it sent, if any. */
export class OnBehalfError extends Error {
  readonly step: OnBehalfStep;
  readonly status: number;
  readonly code: string | null;
  readonly description: string | null;
  constructor(
    step: OnBehalfStep,
    status: number,
    code: string | null,
    more: { what?: string; description?: string | null; cause?: unknown } = {},
  ) {
    super(
      `${more.what ?? step} answered ${status}${code !== null ? ` ${code}` : ""}`,
      more.cause !== undefined ? { cause: more.cause } : undefined,
    );
    this.name = "OnBehalfError";
    this.step = step;
    this.status = status;
    this.code = code;
    this.description = more.description ?? null;
  }

  get reason(): OnBehalfReason {
    return classify(this).reason;
  }
}

export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** How long one call to Varketa or the IdP may take, unless the adopter sets `timeoutMs`. */
export const DEFAULT_TIMEOUT_MS = 15_000;

export const globalFetch: HttpFetch = (url, init) => fetch(url, init) as unknown as ReturnType<HttpFetch>;

/** `f` with a timeout signal on every call. */
export function withTimeout(f: HttpFetch, timeoutMs: number): HttpFetch {
  return (url, init) => f(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
}

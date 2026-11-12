import { OnBehalfError, type OnBehalfReason } from "./http.ts";

// What a failed call drops. Only the settled rows live here; the named refusals (not provisioned, consent,
// an empty election, the door's per-tool refusal) come with Varketa's final refusal table.

export interface Disposition {
  /** Drop the backend's own session (hop 1), so the next mint exchanges it afresh. */
  dropActor: boolean;
  /** Drop this customer's cached credential. */
  dropCustomer: boolean;
  reason: OnBehalfReason;
  /** For `kit_defect`, the server's code. */
  code?: string;
}

const NOTHING: Disposition = { dropActor: false, dropCustomer: false, reason: "unavailable" };
const CUSTOMER: Disposition = { dropActor: false, dropCustomer: true, reason: "unavailable" };
// The one refusal of the customer exchange that names the backend's own session or admission.
const ACTOR_REFUSED = "actor_token_not_usable";
// Refusals of a request the kit built wrong.
const KIT_DEFECTS: ReadonlySet<string> = new Set(["invalid_dpop_proof"]);

export function classify(e: unknown): Disposition {
  // A network error, a timeout or an outage (a 503 included) never invalidates a credential.
  if (!(e instanceof OnBehalfError) || e.status >= 500) return NOTHING;
  // The server refused the kit's own request: a kit defect, not the credential's. It drops nothing.
  if (e.code !== null && KIT_DEFECTS.has(e.code)) {
    return { dropActor: false, dropCustomer: false, reason: "kit_defect", code: e.code };
  }
  if (e.step === "customer" && e.status === 400 && e.code === "invalid_grant" && e.description === ACTOR_REFUSED) {
    return { dropActor: true, dropCustomer: true, reason: "unavailable" };
  }
  // At the door only a 401 says the token was refused; a 403, a 429 or a tool's own error does not.
  if (e.step === "door") return e.status === 401 ? CUSTOMER : NOTHING;
  // Any other 4xx at hops 2 and 3 (hop 3's invalid_grant among them) drops the customer.
  if ((e.step === "customer" || e.step === "door_token") && e.status >= 400) return CUSTOMER;
  return NOTHING;
}

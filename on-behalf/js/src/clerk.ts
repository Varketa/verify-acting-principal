// @varketa/mcp-on-behalf/clerk: the subject token from a Clerk JWT template, through Clerk's Backend API.
// Fetch only, no Clerk SDK. CustomerRef.key is the Clerk session id (`sid`) from the verified session.
import { DEFAULT_TIMEOUT_MS, globalFetch, OnBehalfError, parseJson, withTimeout, type HttpFetch } from "./http.ts";
import type { SubjectTokenProvider } from "./token-source.ts";

export function clerkSubjectTokens(o: {
  secretKey: string;
  template: string;
  apiUrl?: string;
  fetch?: HttpFetch;
  timeoutMs?: number;
}): SubjectTokenProvider {
  const apiUrl = (o.apiUrl ?? "https://api.clerk.com").replace(/\/+$/, "");
  const send = withTimeout(o.fetch ?? globalFetch, o.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  return async (c) => {
    const url = `${apiUrl}/v1/sessions/${encodeURIComponent(c.key)}/tokens/${encodeURIComponent(o.template)}`;
    const res = await send(url, { method: "POST", headers: { authorization: `Bearer ${o.secretKey}` } });
    const body = parseJson(await res.text()) as { jwt?: unknown } | null;
    if (res.status !== 200 || typeof body?.jwt !== "string") {
      throw new OnBehalfError("subject", res.status, null, { what: "Clerk" });
    }
    return body.jwt;
  };
}

// Trace tests triggered by your own test runner (PLT-006): a Playwright or Cypress run sends a
// traceparent we made, then asks Watchtower to judge the trace it produced with a trace test whose
// trigger is `{"runner": {"kind": "playwright" | "cypress" | "k6" | "ci"}}`.

import { randomBytes } from "node:crypto";

export interface Traceparent {
  /** 32 lowercase hex characters. */
  traceId: string;
  /** The W3C `traceparent` header value (sampled). */
  header: string;
}

/** A fresh sampled W3C traceparent. */
export function newTraceparent(): Traceparent {
  const traceId = randomBytes(16).toString("hex");
  return { traceId, header: `00-${traceId}-${randomBytes(8).toString("hex")}-01` };
}

/** What we need of a Playwright `BrowserContext` (or `APIRequestContext` options holder). */
export interface PlaywrightContextLike {
  setExtraHTTPHeaders(headers: Record<string, string>): Promise<void>;
}

/** Every request of the context carries the traceparent; returns it for `runTraceTest`. */
export async function playwrightTraceparent(context: PlaywrightContextLike, tp: Traceparent = newTraceparent()): Promise<Traceparent> {
  await context.setExtraHTTPHeaders({ traceparent: tp.header });
  return tp;
}

/** What we need of Cypress' `cy`. */
export interface CypressLike {
  intercept(matcher: { url: string | RegExp }, handler: (req: { headers: Record<string, string | string[]> }) => void): unknown;
}

/** Requests matching `url` (default: all) carry the traceparent. */
export function cypressTraceparent(cy: CypressLike, url: string | RegExp = /.*/, tp: Traceparent = newTraceparent()): Traceparent {
  cy.intercept({ url }, (req) => { req.headers["traceparent"] = tp.header; });
  return tp;
}

export interface TraceTestRun {
  id: string;
  state: "pending" | "running" | "passed" | "failed" | "error";
  trace_id: string | null;
  result: { error?: string; assertions?: { on: string; name: string; ok: boolean; detail?: string }[] };
}

export interface RunTraceTestOptions {
  /** API base, e.g. https://watchtower.example.com (default $WT_API). */
  api?: string;
  /** Key with manage_monitors (default $WT_TOKEN). */
  token?: string;
  project: string;
  testId: string;
  traceId: string;
  ciRef?: string;
  variables?: Record<string, string>;
  /** How long to wait for the verdict (default 120 s). */
  timeoutMs?: number;
  pollMs?: number;
  fetch?: typeof fetch;
}

const DONE = new Set(["passed", "failed", "error"]);

/** Queues the run, waits for its verdict and throws unless it passed (so the test fails). */
export async function runTraceTest(o: RunTraceTestOptions): Promise<TraceTestRun> {
  const api = (o.api ?? process.env["WT_API"] ?? "").replace(/\/+$/, "");
  const token = o.token ?? process.env["WT_TOKEN"] ?? "";
  if (!api || !token) throw new Error("runTraceTest needs api and token (or WT_API and WT_TOKEN)");
  const f = o.fetch ?? fetch;
  const base = `${api}/v1/projects/${encodeURIComponent(o.project)}`;
  const call = async (method: string, path: string, body?: unknown): Promise<TraceTestRun> => {
    const res = await f(base + path, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status} ${await res.text()}`);
    return (await res.json()) as TraceTestRun;
  };
  let run = await call("POST", `/trace-tests/${encodeURIComponent(o.testId)}/runner-runs`, {
    trace_id: o.traceId, ...(o.ciRef ? { ci_ref: o.ciRef } : {}), ...(o.variables ? { variables: o.variables } : {}),
  });
  const end = Date.now() + (o.timeoutMs ?? 120_000);
  while (!DONE.has(run.state)) {
    if (Date.now() > end) throw new Error(`trace test run ${run.id} is still ${run.state}`);
    await new Promise((r) => setTimeout(r, o.pollMs ?? 2000));
    run = await call("GET", `/trace-test-runs/${encodeURIComponent(run.id)}`);
  }
  if (run.state !== "passed") {
    const bad = (run.result.assertions ?? []).filter((a) => !a.ok).map((a) => `${a.name}: ${a.detail ?? "failed"}`);
    throw new Error(`trace test ${run.state}: ${[run.result.error, ...bad].filter(Boolean).join("; ")}`);
  }
  return run;
}

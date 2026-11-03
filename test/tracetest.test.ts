import assert from "node:assert/strict";
import { test } from "node:test";

import { cypressTraceparent, newTraceparent, playwrightTraceparent, runTraceTest } from "../src/index.ts";

test("traceparents are W3C and reach Playwright and Cypress requests", async () => {
  const tp = newTraceparent();
  assert.match(tp.traceId, /^[0-9a-f]{32}$/);
  assert.match(tp.header, new RegExp(`^00-${tp.traceId}-[0-9a-f]{16}-01$`));
  let headers: Record<string, string> = {};
  const got = await playwrightTraceparent({ setExtraHTTPHeaders: async (h) => { headers = h; } }, tp);
  assert.equal(got, tp);
  assert.deepEqual(headers, { traceparent: tp.header });
  const req = { headers: {} as Record<string, string | string[]> };
  cypressTraceparent({ intercept: (_m, h) => h(req) }, "/api/*", tp);
  assert.equal(req.headers["traceparent"], tp.header);
});

test("runTraceTest queues a runner run, polls and throws on a failed verdict", async () => {
  const seen: { method: string; url: string; body?: unknown }[] = [];
  const states = ["running", "failed"];
  const fake = (async (url: string, init: RequestInit) => {
    seen.push({ method: init.method ?? "GET", url, body: init.body ? JSON.parse(init.body as string) : undefined });
    const state = init.method === "POST" ? "pending" : states.shift();
    const result = state === "failed" ? { assertions: [{ on: "trace", name: "{ db }", ok: false, detail: "0 spans matched" }] } : {};
    return new Response(JSON.stringify({ id: "r1", state, trace_id: null, result }), { status: 200 });
  }) as unknown as typeof fetch;
  const id = "4bf92f3577b34da6a3ce929d0e0e4736";
  await assert.rejects(
    runTraceTest({ api: "https://wt.example/", token: "k", project: "prj_1", testId: "t1", traceId: id, ciRef: "pw-1", pollMs: 1, fetch: fake }),
    /trace test failed: \{ db \}: 0 spans matched/,
  );
  assert.deepEqual(seen[0], { method: "POST", url: "https://wt.example/v1/projects/prj_1/trace-tests/t1/runner-runs", body: { trace_id: id, ci_ref: "pw-1" } });
  assert.equal(seen.length, 3);
  assert.equal(seen[2]!.url, "https://wt.example/v1/projects/prj_1/trace-test-runs/r1");
});

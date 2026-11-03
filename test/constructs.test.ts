import assert from "node:assert/strict";
import { test } from "node:test";

import { API_VERSION, browser, defineProject, http, multiStep, seconds, secret, step, synth, tcp, totp } from "../src/index.ts";

test("constructs synthesize to Monitor and CheckSecret manifests", () => {
  const ms = synth(
    defineProject({
      env: "env_1",
      defaults: { interval: "1m", locations: ["eu-west"], labels: { team: "web" } },
      secrets: [secret("MFA", { fromEnv: "LOGIN_MFA_SEED" })],
      checks: [
        http("api-health", {
          url: "https://api.example.com/health",
          assertions: ["[STATUS] == 200"],
          timeout: "5s",
          auth: { type: "negotiate", username: "probe", realm: "EXAMPLE.COM", kdc: "kdc.example.com", passwordRef: "KRB" },
        }),
        browser("login", {
          steps: [step.goto("https://app.example.com/login"), step.fill("#otp", totp("MFA")), step.click("button")],
          passkeys: [{ rpId: "app.example.com", credentialId: "AAEC", privateKeyRef: "PASSKEY" }],
          interval: 300,
          minFail: 2,
        }),
        tcp("db", { host: "db.example.com", port: 5432, env: "env_2", labels: { team: "data" } }),
      ],
    }),
  );
  assert.equal(ms.length, 4);
  assert.deepEqual(ms[0], { apiVersion: API_VERSION, kind: "CheckSecret", metadata: { name: "MFA" }, spec: { value: "${LOGIN_MFA_SEED}" } });
  const [, api, login, db] = ms;
  assert.deepEqual(api?.metadata, { name: "api-health", labels: { team: "web" } });
  assert.deepEqual(api?.spec, {
    env_id: "env_1", name: "api-health", kind: "http", assertions: ["[STATUS] == 200"], interval_s: 60, timeout_ms: 5000,
    locations: ["eu-west"],
    config: { url: "https://api.example.com/health", auth: { type: "negotiate", username: "probe", realm: "EXAMPLE.COM", kdc: "kdc.example.com", password_ref: "KRB" } },
  });
  assert.equal(login?.spec.interval_s, 300);
  assert.deepEqual(login?.spec.quorum, { min_fail: 2 });
  const cfg = login?.spec.config as { steps: Array<{ value?: string }>; passkeys: unknown[] };
  assert.equal(cfg.steps[1]?.value, "{{totp.MFA}}");
  assert.deepEqual(cfg.passkeys, [{ rp_id: "app.example.com", credential_id: "AAEC", private_key_ref: "PASSKEY" }]);
  assert.equal(db?.spec.env_id, "env_2");
  assert.deepEqual(db?.metadata.labels, { team: "data" });
});

test("bad projects are refused before anything is sent", () => {
  assert.throws(() => synth({ checks: [tcp("db", { host: "h", port: 1 })] }), /set env/);
  assert.throws(() => synth({ env: "e", checks: [tcp("a", { host: "h", port: 1 }), tcp("a", { host: "h", port: 2 })] }), /defined twice/);
  assert.throws(() => http("has space", { url: "https://x" }), /check name/);
  assert.throws(() => totp("1bad"), /not valid/);
  assert.throws(() => secret("OK", { fromEnv: "not-an-env" }), /env var/);
  assert.throws(() => browser("b", { steps: [] }), /needs steps/);
  assert.throws(() => seconds("soon"), /duration/);
  assert.equal(seconds("250ms"), 0.25);
  assert.equal(seconds("2h"), 7200);
});

test("multi-step requests are snake_cased like the API", () => {
  const [m] = synth({
    env: "e",
    checks: [multiStep("flow", { steps: [{ name: "a", request: { url: "https://x", maxRedirects: 2, headers: { "X-Trace": "1" } } }] })],
  });
  const steps = (m?.spec.config as { steps: Array<{ request: Record<string, unknown> }> }).steps;
  assert.deepEqual(steps[0]?.request, { url: "https://x", headers: { "X-Trace": "1" }, max_redirects: 2 });
});

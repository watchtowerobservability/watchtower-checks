import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { main, parseArgs, watchSources, writeManifests } from "../src/cli.ts";
import { synth, tcp } from "../src/index.ts";

const lib = pathToFileURL(join(import.meta.dirname, "..", "src", "index.ts")).href;

function project(names: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "wt-checks-"));
  const checks = names.map((n) => `tcp(${JSON.stringify(n)}, { host: "db.example.com", port: 5432 })`).join(", ");
  writeFileSync(join(dir, "checks.config.ts"), `import { defineProject, tcp } from ${JSON.stringify(lib)};\nexport default defineProject({ env: "env_1", checks: [${checks}] });\n`);
  return dir;
}

test("parseArgs keeps wtctl flags and resolves paths", () => {
  const o = parseArgs(["deploy", "--config", "c.ts", "--project", "prj_1", "--prune"]);
  assert.equal(o.cmd, "deploy");
  assert.ok(o.config.endsWith("c.ts"));
  assert.deepEqual(o.pass, ["--project", "prj_1", "--prune"]);
  assert.throws(() => parseArgs(["publish"]), /usage/);
  assert.throws(() => parseArgs(["synth", "--out"]), /needs a value/);
});

test("writeManifests rewrites only changes and removes stale manifests after writing", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "wt-out-")), "out");
  const two = synth({ env: "e", checks: [tcp("a", { host: "h", port: 1 }), tcp("b", { host: "h", port: 2 })] });
  assert.deepEqual(writeManifests(dir, two), { written: 2, removed: 0 });
  const before = statSync(join(dir, "Monitor-a.json")).mtimeMs;
  assert.deepEqual(writeManifests(dir, two), { written: 0, removed: 0 });
  assert.equal(statSync(join(dir, "Monitor-a.json")).mtimeMs, before);
  assert.deepEqual(writeManifests(dir, two.slice(0, 1)), { written: 0, removed: 1 });
  assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".json")), ["Monitor-a.json"]);
  const foreign = mkdtempSync(join(tmpdir(), "wt-foreign-"));
  writeFileSync(join(foreign, "keep.json"), "{}");
  assert.throws(() => writeManifests(foreign, two), /not a wt-checks output/);
});

test("deploy synthesizes the config and hands the directory to wtctl apply", async () => {
  const dir = project(["db", "cache"]);
  const fake = join(dir, "fake-wtctl.mjs");
  writeFileSync(fake, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(join(dir, "args.json"))}, JSON.stringify(process.argv.slice(2)));\n`);
  process.env.WTCTL = fake;
  const out = join(dir, ".watchtower", "checks");
  const code = await main(["deploy", "--config", join(dir, "checks.config.ts"), "--out", out, "--project", "prj_1"], () => {});
  assert.equal(code, 0);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, "args.json"), "utf8")), ["apply", "-f", out, "--project", "prj_1"]);
  const m = JSON.parse(readFileSync(join(out, "Monitor-db.json"), "utf8"));
  assert.equal(m.spec.kind, "tcp");
  assert.equal(await main(["synth", "--config", join(dir, "missing.ts"), "--out", out], () => {}), 1);
});

test("watchSources fires once per burst of source edits and ignores the output directory", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wt-watch-"));
  const out = join(dir, "out");
  mkdirSync(out);
  let calls = 0;
  const stop = watchSources(dir, [out], () => calls++, 50);
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
  try {
    await wait(100);
    writeFileSync(join(out, "Monitor-a.json"), "{}");
    writeFileSync(join(dir, "notes.txt"), "x");
    await wait(200);
    assert.equal(calls, 0);
    writeFileSync(join(dir, "checks.config.ts"), "export default 1\n");
    writeFileSync(join(dir, "more.ts"), "export const a = 1\n");
    for (let i = 0; i < 40 && calls === 0; i++) await wait(50);
    await wait(150);
    assert.equal(calls, 1);
  } finally {
    stop();
  }
});

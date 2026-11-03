// Checks as code: monitors written as TypeScript constructs, synthesized into the
// `watchtower.dev/v1` manifests that `wtctl apply` and `wtctl checks watch` sync through the API.

export const API_VERSION = "watchtower.dev/v1";

export type ManifestKind = "Monitor" | "CheckSecret";

export interface Manifest {
  apiVersion: typeof API_VERSION;
  kind: ManifestKind;
  metadata: { name: string; labels?: Record<string, string> };
  spec: Record<string, unknown>;
}

/** A duration: seconds as a number, or "500ms", "30s", "5m", "1h". */
export type Duration = number | string;

export interface Retry {
  mode?: "none" | "fixed" | "linear" | "exponential";
  max?: number;
  delayMs?: number;
}

/** What every check may set; a project's `defaults` fill what a check leaves out. */
export interface CheckProps {
  env?: string;
  service?: string;
  interval?: Duration;
  timeout?: Duration;
  locations?: string[];
  assertions?: string[];
  retry?: Retry;
  /** Locations that must fail before the check is down. */
  minFail?: number;
  /** A passing check slower than this is degraded, not down. */
  degraded?: Duration;
  alert?: boolean;
  enabled?: boolean;
  labels?: Record<string, string>;
  /** Further MonitorSpec fields, sent as they are (snake_case, e.g. escalation settings). */
  extra?: Record<string, unknown>;
}

export interface Check {
  readonly name: string;
  readonly kind: string;
  readonly config: Record<string, unknown>;
  readonly props: CheckProps;
}

export interface SecretDef {
  readonly name: string;
  /** The environment variable that holds the value when the manifests are applied. */
  readonly fromEnv: string;
}

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,199}$/i;
const SECRET_RE = /^[A-Za-z][A-Za-z0-9_]*$/;

/** `{{secret.NAME}}`: a vault value, substituted when the check runs. */
export function secretRef(name: string): string {
  if (!SECRET_RE.test(name)) throw new Error(`secret name ${JSON.stringify(name)} is not valid`);
  return `{{secret.${name}}}`;
}

/** `{{totp.NAME}}`: the current one-time code of the TOTP seed stored as vault secret NAME. */
export function totp(name: string): string {
  if (!SECRET_RE.test(name)) throw new Error(`secret name ${JSON.stringify(name)} is not valid`);
  return `{{totp.${name}}}`;
}

/** A vault secret whose value comes from an environment variable at apply time (never from code). */
export function secret(name: string, opts: { fromEnv: string }): SecretDef {
  if (!SECRET_RE.test(name)) throw new Error(`secret name ${JSON.stringify(name)} is not valid`);
  if (!SECRET_RE.test(opts.fromEnv)) throw new Error(`fromEnv ${JSON.stringify(opts.fromEnv)} is not an env var name`);
  return { name, fromEnv: opts.fromEnv };
}

/** Any check kind with its driver config (see docs/product/uptime/check-types.md). */
export function check(name: string, kind: string, config: Record<string, unknown>, props: CheckProps = {}): Check {
  if (!NAME_RE.test(name)) throw new Error(`check name ${JSON.stringify(name)}: letters, digits, . _ - (at most 200)`);
  if (!/^[a-z0-9_]+$/.test(kind)) throw new Error(`check ${name}: kind ${JSON.stringify(kind)} is not valid`);
  return { name, kind, config, props };
}

export interface HttpConfig {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  maxRedirects?: number;
  tlsVerify?: boolean;
  auth?:
    | { type: "basic"; username: string; passwordRef: string }
    | { type: "bearer"; tokenRef: string }
    | { type: "negotiate"; username: string; realm: string; kdc: string; passwordRef: string; spn?: string };
}

function snake(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined) continue;
    const key = k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
    out[key] = v !== null && typeof v === "object" && !Array.isArray(v) && key !== "headers" ? snake(v as Record<string, unknown>) : v;
  }
  return out;
}

export function http(name: string, cfg: HttpConfig & CheckProps): Check {
  const { url, method, headers, body, maxRedirects, tlsVerify, auth, ...props } = cfg;
  return check(name, "http", snake({ url, method, headers, body, maxRedirects, tlsVerify, auth }), props);
}

export interface BrowserStep {
  action: string;
  [field: string]: unknown;
}

/** The browser step script; `step.fill("#otp", totp("MFA"))` types a fresh code. */
export const step = {
  goto: (url: string): BrowserStep => ({ action: "goto", url }),
  click: (selector: string): BrowserStep => ({ action: "click", selector }),
  fill: (selector: string, value: string): BrowserStep => ({ action: "fill", selector, value }),
  press: (key: string, selector?: string): BrowserStep => ({ action: "press", value: key, ...(selector ? { selector } : {}) }),
  waitFor: (selector: string): BrowserStep => ({ action: "wait_for", selector }),
  assertText: (selector: string, text: string): BrowserStep => ({ action: "assert_text", selector, text }),
  assertVisible: (selector: string): BrowserStep => ({ action: "assert_visible", selector }),
  evaluate: (script: string, value?: string): BrowserStep => ({ action: "evaluate", script, ...(value ? { value } : {}) }),
};

export interface Passkey {
  rpId: string;
  credentialId: string;
  privateKeyRef: string;
  userHandle?: string;
  signCount?: number;
  discoverable?: boolean;
}

export interface BrowserConfig {
  steps: BrowserStep[];
  emulation?: Record<string, unknown>;
  capture?: Array<"har" | "trace" | "video">;
  passkeys?: Passkey[];
}

export function browser(name: string, cfg: BrowserConfig & CheckProps): Check {
  const { steps, emulation, capture, passkeys, ...props } = cfg;
  if (steps.length === 0) throw new Error(`browser check ${name} needs steps`);
  const config: Record<string, unknown> = { steps };
  if (emulation) config.emulation = emulation;
  if (capture) config.capture = capture;
  if (passkeys) config.passkeys = passkeys.map((p) => snake({ ...p }));
  return check(name, "browser", config, props);
}

export interface MultiStepStep {
  name: string;
  request: HttpConfig;
  extract?: Record<string, string>;
  assertions?: string[];
}

export function multiStep(name: string, cfg: { steps: MultiStepStep[] } & CheckProps): Check {
  const { steps, ...props } = cfg;
  const out = steps.map((s) => {
    const { url, method, headers, body, maxRedirects, tlsVerify, auth } = s.request;
    return { name: s.name, request: snake({ url, method, headers, body, maxRedirects, tlsVerify, auth }), extract: s.extract, assertions: s.assertions };
  });
  return check(name, "multistep", { steps: out }, props);
}

export function tcp(name: string, cfg: { host: string; port: number } & CheckProps): Check {
  const { host, port, ...props } = cfg;
  return check(name, "tcp", { host, port }, props);
}

export function dns(name: string, cfg: { host: string; recordType?: string; server?: string } & CheckProps): Check {
  const { host, recordType, server, ...props } = cfg;
  return check(name, "dns", snake({ host, recordType, server }), props);
}

/** Seconds of a Duration (fractions kept for "ms"). */
export function seconds(d: Duration): number {
  if (typeof d === "number") return d;
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(d.trim());
  if (!m) throw new Error(`duration ${JSON.stringify(d)}: use a number of seconds or 500ms, 30s, 5m, 1h`);
  const n = Number(m[1]);
  if (m[2] === "ms") return n / 1000;
  return n * ({ s: 1, m: 60, h: 3600 } as const)[m[2] as "s" | "m" | "h"];
}

export interface ProjectDef {
  /** The environment id every check runs in unless it sets `env`. */
  env?: string;
  defaults?: CheckProps;
  checks: Check[];
  secrets?: SecretDef[];
}

/** The default export of a checks config file. */
export function defineProject(def: ProjectDef): ProjectDef {
  return def;
}

function monitor(c: Check, def: ProjectDef): Manifest {
  const p: CheckProps = { ...def.defaults, ...c.props, labels: { ...def.defaults?.labels, ...c.props.labels } };
  const env = p.env ?? def.env;
  if (!env) throw new Error(`check ${c.name}: set env on the project or the check`);
  const spec: Record<string, unknown> = { env_id: env, name: c.name, kind: c.kind, config: c.config };
  if (p.service) spec.service = p.service;
  if (p.assertions) spec.assertions = p.assertions;
  if (p.interval !== undefined) spec.interval_s = Math.round(seconds(p.interval));
  if (p.timeout !== undefined) spec.timeout_ms = Math.round(seconds(p.timeout) * 1000);
  if (p.locations) spec.locations = p.locations;
  if (p.retry) spec.retry = snake({ ...p.retry });
  if (p.minFail !== undefined) spec.quorum = { min_fail: p.minFail };
  if (p.degraded !== undefined) spec.degraded_ms = Math.round(seconds(p.degraded) * 1000);
  if (p.alert !== undefined) spec.alert = p.alert;
  if (p.enabled !== undefined) spec.enabled = p.enabled;
  Object.assign(spec, p.extra);
  const labels = p.labels && Object.keys(p.labels).length > 0 ? p.labels : undefined;
  return { apiVersion: API_VERSION, kind: "Monitor", metadata: labels ? { name: c.name, labels } : { name: c.name }, spec };
}

/** The manifests of a project, secrets first (monitors reference them). Throws on a bad project. */
export function synth(def: ProjectDef): Manifest[] {
  const seen = new Set<string>();
  const once = (id: string) => {
    if (seen.has(id)) throw new Error(`${id} is defined twice`);
    seen.add(id);
  };
  const out: Manifest[] = [];
  for (const s of def.secrets ?? []) {
    once(`CheckSecret/${s.name}`);
    out.push({ apiVersion: API_VERSION, kind: "CheckSecret", metadata: { name: s.name }, spec: { value: `\${${s.fromEnv}}` } });
  }
  for (const c of def.checks) {
    once(`Monitor/${c.name}`);
    out.push(monitor(c, def));
  }
  return out;
}

export { cypressTraceparent, newTraceparent, playwrightTraceparent, runTraceTest } from "./tracetest.ts";
export type { CypressLike, PlaywrightContextLike, RunTraceTestOptions, Traceparent, TraceTestRun } from "./tracetest.ts";

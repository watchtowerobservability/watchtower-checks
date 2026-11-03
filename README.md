# @watchtowerobservability/checks

Watchtower monitors as TypeScript. A config file default-exports a project; `wt-checks` turns it
into `watchtower.dev/v1` manifests and syncs them through the API with `wtctl` (same engine as
`wtctl apply` and the Terraform provider).

```ts
// checks.config.ts
import { browser, defineProject, http, secret, step, totp } from "@watchtowerobservability/checks";

export default defineProject({
  env: "env_123",
  defaults: { interval: "1m", locations: ["eu-west", "us-east"] },
  secrets: [secret("LOGIN_MFA", { fromEnv: "LOGIN_MFA_SEED" })],
  checks: [
    http("api-health", { url: "https://api.example.com/health", assertions: ["[STATUS] == 200"] }),
    browser("login", {
      steps: [step.goto("https://app.example.com/login"), step.fill("#otp", totp("LOGIN_MFA")), step.click("button[type=submit]")],
    }),
  ],
});
```

```sh
npx wt-checks test   --project prj_1   # synth + wtctl diff: what deploy would change
npx wt-checks deploy --project prj_1   # synth + wtctl apply (add --prune to delete removed checks)
npx wt-checks watch  --project prj_1   # apply now and on every save (hot reload)
```

`WT_API` and `WT_API_KEY` (or `--api`, `--key`) reach your Watchtower; `WTCTL` picks the `wtctl`
binary. Secret values never live in code: `secret(name, { fromEnv })` reads an environment variable
at apply time, and checks reference it with `secretRef(name)` or `totp(name)`. Node 22.18 or newer
loads the `.ts` config directly.

# Triage suspicious logins

A [Flue](https://flueframework.com) agent that investigates suspicious Cloudflare Access logins. Tag it in Slack, and it pulls the user's Access logs, enriches every source IP with Cloudflare threat intelligence, scores the risk against a rubric, and posts a structured report back to the thread.

**[Full walkthrough: Triage Suspicious Logins with Flue and Slack](https://flueframework.com/learn/triage-suspicious-logins/)** — deploying, connecting Slack, running it locally, and tuning the rubric.

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jamesqquick/triage-suspicious-login-agent)

Have a Cloudflare API token and your account ID ready — the setup page requires both, and tells you which scopes the token needs. Leave the two Slack variables blank; you add them once you have a Worker URL.

The Workers AI binding and the SQLite-backed Durable Object are declared in `wrangler.jsonc` and provisioned automatically. AI Gateway is not provisioned, and does not need to be: the Worker requests gateway `default`, which AI Gateway creates on the first authenticated request.

Sending your first investigation and wiring up Slack are covered in the [walkthrough](https://flueframework.com/learn/triage-suspicious-logins/).

## How it works

```
Slack @mention
   └─ Worker (Hono) → dispatch → LoginTriage (one Durable Object per thread)
        ├─ skill: triage              (risk-scoring rubric)
        ├─ tool: get_access_logs      (Cloudflare Access Logs API)
        ├─ tool: get_indicator_intel  (Cloudflare Intel API)
        └─ tool: post_triage_report   (Slack Block Kit, or run output locally)
```

| Path | What it is |
| --- | --- |
| `src/agents/login-triage.ts` | The agent. Hooks compose its model, skill, and tools; the return value is its instruction. |
| `src/skills/triage/SKILL.md` | The risk-scoring rubric. Edit this to tune verdicts — no code changes. |
| `src/tools/access-logs.ts` | `get_access_logs` — Access authentication events for a user and window. |
| `src/tools/intel.ts` | `get_indicator_intel` — Cloudflare Intel reputation, with a per-indicator `status`. |
| `src/tools/slack-report.ts` | `post_triage_report` — schema-validated verdict, posted as Block Kit. |
| `src/channels/slack.ts` | Slack ingress. Verifies the signature, strips the mention, dispatches per thread. |
| `src/app.ts` | The route map. |

### Coverage gaps are not clean verdicts

`get_indicator_intel` returns `status: "enriched"` or `status: "lookup_failed"` for every indicator, and the rubric states that a `lookup_failed` entry must never lower the risk level. A security tool that reports "could not check" as "clean" is worse than no tool, so the distinction is representable in the data and explicit in `SKILL.md`.

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm predeploy   # vite build + wrangler deploy --dry-run
```

Running the agent locally needs a direct model provider key, since `flue run` has no Workers AI binding to borrow. The [walkthrough](https://flueframework.com/learn/triage-suspicious-logins/#run-it-locally) covers the setup.

## License

MIT

# Triage suspicious logins

A [Flue](https://flueframework.com) agent that investigates suspicious Cloudflare Access logins. Tag it in Slack, and it pulls the user's Access logs, enriches every source IP with Cloudflare threat intelligence, scores the risk against a rubric, and posts a structured report back to the thread.

Full walkthrough: **[Triage Suspicious Logins with Flue and Slack](https://flueframework.com/learn/triage-suspicious-logins/)**

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jamesqquick/triage-suspicious-login-agent)

Have `CF_API_TOKEN` and `CF_ACCOUNT_ID` in hand before you start — the setup page requires both. The token needs `Account Intel: Read` and `Access: Audit Logs: Read`.

Leave `SLACK_BOT_TOKEN` and `SLACK_SIGNING_SECRET` blank; you add them in [Connect Slack](#connect-slack) once you have a Worker URL.

The Workers AI binding and the SQLite-backed Durable Object are declared in `wrangler.jsonc` and provisioned automatically. AI Gateway is not provisioned, and does not need to be: the Worker requests gateway `default`, which AI Gateway creates on the first authenticated request.

### Send your first investigation

```bash
curl -X POST https://<your-worker>.workers.dev/agents/login-triage \
  -H 'Content-Type: application/json' \
  -d '{"message":"investigate employee@company.com"}'
```

### Connect Slack

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
2. Add the `app_mentions:read` and `chat:write` bot scopes, then install the app
3. Add the two secrets:

   ```bash
   wrangler secret put SLACK_BOT_TOKEN
   wrangler secret put SLACK_SIGNING_SECRET
   ```

4. Under **Event Subscriptions**, set the request URL to `https://<your-worker>.workers.dev/channels/slack/events` and subscribe to the `app_mention` bot event

Then mention the bot:

```
@login-triage investigate employee@company.com
```

## Run it locally

```bash
git clone https://github.com/jamesqquick/triage-suspicious-login-agent
cd triage-suspicious-login-agent
pnpm install
cp .env.example .env
```

Fill in `CF_API_TOKEN` and `CF_ACCOUNT_ID`. Then add two more variables that are **not** in `.env.example`:

```bash
MODEL=openai/gpt-4o
OPENAI_API_KEY=sk-...
```

`flue run` is an ordinary Node process, so there is no Workers AI binding to borrow — a local run needs a direct provider key. These two are deliberately excluded from `.env.example` because every variable in that file becomes a required prompt on the Deploy page, and the deployed Worker needs neither. Deployed, `MODEL` stays `cloudflare/openai/gpt-4o` (set in `wrangler.jsonc`) and routes through the binding.

Then run the agent:

```bash
pnpm flue run src/agents/login-triage.ts --message "investigate employee@company.com"
```

Or with the shorthand script:

```bash
pnpm agent "investigate employee@company.com"
```

`flue run` executes the agent with no HTTP server and no Slack channel, which makes it the right place to develop the rubric — you get the report as terminal output instead of a thread message.

Because it reads live Access logs, running against the same user twice gives you a stable dataset to compare rubric edits against, as long as you pin an explicit window in the prompt rather than letting it default to "the last 7 days":

```bash
pnpm agent "investigate employee@company.com from 2026-07-01T00:00:00Z to 2026-07-08T00:00:00Z"
```

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
pnpm typecheck
pnpm test
pnpm predeploy   # vite build + wrangler deploy --dry-run
```

## Make it your own

- **Tune the rubric.** Edit `SKILL.md`, re-run against a pinned time window, and see how the verdict moves.
- **Change the delivery surface.** Swap the Slack channel for GitHub, Telegram, or email — the agent and tools don't change.
- **Add a signal.** Any Cloudflare API can become a tool. Gateway DNS/HTTP logs need Logpush to R2 and only cover traffic from the moment you enable it; Cloudforce One threat events need a paid subscription.
- **Split the work with subagents.** As tool count grows, group collection and enrichment into subagents so each gets its own focused context.
- **Persist verdicts.** Write each report to D1 or KV to track repeat offenders across investigations.
- **Use a dedicated AI Gateway.** Replace `default` in `src/app.ts` with a named gateway to isolate this project's logs, caching, and budget.

## License

MIT

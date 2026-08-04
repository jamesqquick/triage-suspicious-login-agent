import { createChannelRouter, setProvider } from '@flue/runtime';
import { cloudflareBindingProvider } from '@flue/runtime/cloudflare/workers-ai';
import { createAgentRouter } from '@flue/runtime/routing';
import { env } from 'cloudflare:workers';
import { Hono } from 'hono';
import { LoginTriage } from './agents/login-triage.ts';
import { channel } from './channels/slack.ts';

// Route model calls through AI Gateway for request logging, rate limiting, and
// budgets. Response caching is intentionally left off (Gateway default): every
// triage must reflect live reasoning, never a stale cached LLM response.
setProvider(
  cloudflareBindingProvider({
    binding: env.AI,
    // `default` is created automatically on first authenticated request.
    gateway: { id: 'default' },
  }),
);

const app = new Hono();
app.route('/agents/login-triage', createAgentRouter(LoginTriage));

// Slack ingress at /channels/slack/events — point Slack's Event Subscriptions URL
// here (app_mention). Wrapped in createChannelRouter so the returned Hono is typed
// against this app's hono version (@flue/slack bundles an older, incompatible one).
app.route('/channels/slack', createChannelRouter(channel.routes));

export default app;

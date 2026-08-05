import { createChannelRouter, setProvider } from '@flue/runtime';
import { cloudflareBindingProvider } from '@flue/runtime/cloudflare/workers-ai';
import { createAgentRouter } from '@flue/runtime/routing';
import { env } from 'cloudflare:workers';
import { Hono } from 'hono';
import { LoginTriage } from './agents/login-triage.ts';
import { channel } from './channels/slack.ts';

// Response caching is intentionally left off (Gateway default): every triage
// must reflect live reasoning, never a stale cached response.
setProvider(
  cloudflareBindingProvider({
    binding: env.AI,
    // `default` is created automatically on first authenticated request.
    gateway: { id: 'default' },
  }),
);

const app = new Hono();
app.route('/agents/login-triage', createAgentRouter(LoginTriage));

// Wrapped in createChannelRouter so the returned Hono is typed against this
// app's hono version (@flue/slack bundles an older, incompatible one).
if (channel) {
  app.route('/channels/slack', createChannelRouter(channel.routes));
} else {
  app.all('/channels/slack/*', (c) =>
    c.json({ error: 'Slack ingress is disabled: SLACK_SIGNING_SECRET is not set.' }, 503),
  );
}

export default app;

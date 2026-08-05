import { dispatch } from '@flue/runtime';
import { createSlackChannel, type SlackChannel, type SlackThreadRef } from '@flue/slack';
import { LoginTriage } from '../agents/login-triage.ts';
import { getSlackConfig } from '../lib/config.ts';

function cleanMention(text: string): string {
  return text.replace(/<@[^>]+>/g, '').trim();
}

function build(signingSecret: string): SlackChannel {
  const slack: SlackChannel = createSlackChannel({
    signingSecret,
    async events({ payload }) {
      if (payload.type !== 'event_callback') return;
      if (payload.event.type !== 'app_mention') return;

      const event = payload.event;
      const thread: SlackThreadRef = {
        teamId: payload.team_id,
        channelId: event.channel,
        threadTs: event.thread_ts ?? event.ts,
      };

      // Set here in verified webhook code, so tools may trust them as identity.
      const attributes: Record<string, string> = { eventId: payload.event_id };
      if (event.user) attributes.requestedBy = event.user;

      // Dispatched as a signal, not a user message, so the multi-participant
      // thread keeps its metadata.
      await dispatch(LoginTriage, {
        id: slack.instanceId(thread),
        initialData: thread,
        message: {
          kind: 'signal',
          type: 'slack.app_mention',
          body: cleanMention(event.text ?? ''),
          attributes,
        },
      });
    },
  });

  return slack;
}

// Slack ingress is optional, and deliberately so: SLACK_SIGNING_SECRET is set
// after the first deploy, once a Slack app exists to point at the Worker URL.
// createSlackChannel() throws on an empty secret, and this module is evaluated
// during script validation, so an unconditional call fails the deploy outright.
// Build the channel only when the secret is present; app.ts serves 503 on
// /channels/slack/* otherwise, and the agent's HTTP route is unaffected.
// Secrets are readable in top-level scope, and `wrangler secret put` deploys a
// new version, so setting the secret mounts the channel on the next version.
export const channel: SlackChannel | undefined = (() => {
  const { signingSecret } = getSlackConfig();
  return signingSecret ? build(signingSecret) : undefined;
})();

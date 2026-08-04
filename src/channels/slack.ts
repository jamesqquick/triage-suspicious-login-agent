import { dispatch } from '@flue/runtime';
import { createSlackChannel, type SlackThreadRef } from '@flue/slack';
import { LoginTriage } from '../agents/login-triage.ts';
import { getSlackConfig } from '../lib/config.ts';

// Strip leading bot @-mentions so the agent sees just the request text.
function cleanMention(text: string): string {
  return text.replace(/<@[^>]+>/g, '').trim();
}

// An empty signingSecret (SLACK_SIGNING_SECRET unset) makes verification fail
// closed — rejecting rather than trusting unverified webhooks.
export const channel = createSlackChannel({
  signingSecret: getSlackConfig().signingSecret,
  async events({ payload }) {
    if (payload.type !== 'event_callback') return;
    if (payload.event.type !== 'app_mention') return;

    const event = payload.event;
    const thread: SlackThreadRef = {
      teamId: payload.team_id,
      channelId: event.channel,
      threadTs: event.thread_ts ?? event.ts,
    };

    // Carried as a signal (not a user message) so the multi-participant thread
    // keeps its metadata. `attributes` are set here in verified webhook code, so
    // tools/instructions can trust them (see useDelivery in the agent).
    const attributes: Record<string, string> = { eventId: payload.event_id };
    if (event.user) attributes.requestedBy = event.user;

    // One agent instance per Slack thread, seeded so the report tool can post back.
    await dispatch(LoginTriage, {
      id: channel.instanceId(thread),
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

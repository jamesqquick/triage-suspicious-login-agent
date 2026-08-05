import { dispatch } from '@flue/runtime';
import { createSlackChannel, type SlackThreadRef } from '@flue/slack';
import { LoginTriage } from '../agents/login-triage.ts';
import { getSlackConfig } from '../lib/config.ts';

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

    // Set here in verified webhook code, so tools may trust them as identity.
    const attributes: Record<string, string> = { eventId: payload.event_id };
    if (event.user) attributes.requestedBy = event.user;

    // Dispatched as a signal, not a user message, so the multi-participant
    // thread keeps its metadata.
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

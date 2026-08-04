'use agent';
import { useDelivery, useInitialData, useModel, useSkill, useTool } from '@flue/runtime';
import * as v from 'valibot';
import { getModel } from '../lib/config.ts';
import { createTriageReportTool } from '../tools/slack-report.ts';
import { getAccessLogs } from '../tools/access-logs.ts';
import { getIndicatorIntel } from '../tools/intel.ts';
import triageSkill from '../skills/triage/SKILL.md';

export function LoginTriage() {
  useModel(getModel());

  // Set from the originating Slack thread so the report tool can post back;
  // undefined under `flue run`.
  const slackThread = useInitialData<v.InferOutput<typeof LoginTriage.initialData>>();

  useSkill(triageSkill);
  useTool(getAccessLogs);
  useTool(getIndicatorIntel);
  useTool(createTriageReportTool(slackThread));

  // Trusted requester identity: set on the signal's `attributes` by verified
  // webhook code, never from model input.
  const delivery = useDelivery();
  const requestedBy = delivery.kind === 'signal' ? delivery.attributes?.requestedBy : undefined;

  return [
    'You are a security analyst triaging a suspicious login. Investigate the given user and report your findings.',
    requestedBy ? `This investigation was requested by Slack user <@${requestedBy}>.` : '',
    'If no time window is given, default to the last 7 days ending now.',
    'Compute concrete ISO 8601 fromTime/toTime values yourself — never stop to ask for a time range.',
  ]
    .filter(Boolean)
    .join(' ');
}

LoginTriage.agentName = 'login-triage';

// Optional so local `flue run` works with no Slack thread; a malformed Slack
// dispatch fails fast at admission instead of seeding a broken conversation.
LoginTriage.initialData = v.optional(
  v.object({ teamId: v.string(), channelId: v.string(), threadTs: v.string() }),
);

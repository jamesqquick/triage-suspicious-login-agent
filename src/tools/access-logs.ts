import { defineTool } from '@flue/runtime';
import * as v from 'valibot';
import { getCloudflareClient } from '../lib/cf-client.ts';
import { getCloudflareApiConfig } from '../lib/config.ts';
import { asJson } from '../lib/json.ts';
import { type AccessRecord, computeSignals } from '../lib/signals.ts';

// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/logs/subresources/access_requests/methods/list/
// Fields are snake_case, and there is no device id — Access logs identify the
// user and source IP, not the device.
export const getAccessLogs = defineTool({
  name: 'get_access_logs',
  description:
    'Fetch Cloudflare Access authentication logs for a user. ' +
    'Returns up to 300 login/logout events: allowed, app_domain, ip_address, created_at. ' +
    'Also returns a precomputed "signals" block — deniedCount, the full distinctIps list, ' +
    'denialBursts, off-hours counts in UTC, the triggeringEvent to cite, and a riskFloor. ' +
    'Use those values directly; do not recount them from the records.',
  input: v.object({
    userEmail: v.pipe(v.string(), v.email(), v.description('User email address to filter on')),
    fromTime: v.pipe(v.string(), v.description('ISO 8601 window start')),
    toTime: v.pipe(v.string(), v.description('ISO 8601 window end')),
  }),
  async run({ data }) {
    const { accountId } = getCloudflareApiConfig();
    const records = await getCloudflareClient().zeroTrust.access.logs.accessRequests.list({
      account_id: accountId,
      email: data.userEmail,
      emailOp: 'eq',
      since: data.fromTime,
      until: data.toTime,
      limit: 300,
      direction: 'desc',
    });

    // signals is additive: records/total/dataset keep their shape. The counting is
    // done here so the model reads numbers instead of estimating them.
    return {
      output: asJson({
        records,
        total: records.length,
        dataset: 'access_requests',
        signals: computeSignals(records as AccessRecord[]),
      }),
    };
  },
});

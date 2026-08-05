import { defineTool } from '@flue/runtime';
import * as v from 'valibot';
import { cfErrorNote, getCloudflareClient } from '../lib/cf-client.ts';
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
    'Use those values directly; do not recount them from the records. ' +
    'If the query fails this returns "fetchError" with an empty record set rather than erroring; ' +
    'signals.riskFloor is then "unknown". Still file a report in that case — say the logs could not ' +
    'be read, and do not describe the user as having no login activity.',
  input: v.object({
    userEmail: v.pipe(v.string(), v.email(), v.description('User email address to filter on')),
    fromTime: v.pipe(v.string(), v.description('ISO 8601 window start')),
    toTime: v.pipe(v.string(), v.description('ISO 8601 window end')),
  }),
  async run({ data }) {
    const { accountId } = getCloudflareApiConfig();

    // Failures are returned as data, not thrown, for the same reason get_indicator_intel
    // does it: a thrown tool produces no signals block, so no rubric rule applies and
    // the model is left to improvise. Observed consequence — on a 403 it explained the
    // error in prose and never called post_triage_report, and since that tool is the
    // only thing that writes to Slack, the requesting analyst got silence. Returning
    // the error keeps the failure inside the scoring path, where it floors at `unknown`.
    let records: AccessRecord[];
    let fetchError: string | null = null;
    try {
      records = (await getCloudflareClient().zeroTrust.access.logs.accessRequests.list({
        account_id: accountId,
        email: data.userEmail,
        emailOp: 'eq',
        since: data.fromTime,
        until: data.toTime,
        limit: 300,
        direction: 'desc',
      })) as AccessRecord[];
    } catch (err) {
      records = [];
      fetchError = cfErrorNote(err).note;
    }

    // signals is additive: records/total/dataset keep their shape. The counting is
    // done here so the model reads numbers instead of estimating them.
    return {
      output: asJson({
        records,
        total: records.length,
        dataset: 'access_requests',
        fetchError,
        signals: computeSignals(records, fetchError),
      }),
    };
  },
});

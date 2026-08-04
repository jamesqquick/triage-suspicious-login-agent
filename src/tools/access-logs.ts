import { defineTool } from '@flue/runtime';
import * as v from 'valibot';
import { getCloudflareClient } from '../lib/cf-client.ts';
import { getCloudflareApiConfig } from '../lib/config.ts';
import { asJson } from '../lib/json.ts';

// AccessRequest records come from GET /accounts/{id}/access/logs/access_requests.
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/logs/subresources/access_requests/methods/list/
// Fields are snake_case, and there is no DeviceID — Access logs identify the user
// and source IP, not the device.
export const getAccessLogs = defineTool({
  name: 'get_access_logs',
  description:
    'Fetch Cloudflare Access authentication logs for a user. ' +
    'Returns up to 300 login/logout events: allowed, app_domain, ip_address, created_at.',
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

    return { output: asJson({ records, total: records.length, dataset: 'access_requests' }) };
  },
});

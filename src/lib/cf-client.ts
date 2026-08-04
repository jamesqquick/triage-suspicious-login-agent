import Cloudflare, { APIError } from 'cloudflare';
import { getCloudflareApiConfig } from './config.ts';

let defaultClient: Cloudflare | undefined;
let testClient: Cloudflare | undefined;

export function getCloudflareClient(): Cloudflare {
  if (testClient) return testClient;
  if (!defaultClient) {
    const { apiToken } = getCloudflareApiConfig();
    defaultClient = new Cloudflare({ apiToken });
  }
  return defaultClient;
}

export function __setCloudflareClientForTests(client: Cloudflare | undefined): void {
  testClient = client;
  defaultClient = undefined;
}

// Maps an SDK error to a short status note. A failed or unknown lookup must
// never be reported as clean, so callers attach the note to a "lookup_failed"
// result instead of throwing to the model.
export interface CfErrorNote {
  status?: number;
  notFound: boolean;
  note: string;
}

export function cfErrorNote(err: unknown): CfErrorNote {
  if (err instanceof APIError && typeof err.status === 'number') {
    const status = err.status;
    if (status === 404) return { status, notFound: true, note: 'no record found (404)' };
    if (status === 401 || status === 403) {
      return { status, notFound: false, note: `no read access (${status})` };
    }
    if (status === 429) return { status, notFound: false, note: 'rate limited (429)' };
    if (status >= 500) return { status, notFound: false, note: `upstream error (${status})` };
    return { status, notFound: false, note: `request failed (${status})` };
  }
  return { notFound: false, note: err instanceof Error ? err.message : String(err) };
}

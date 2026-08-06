export class MissingConfigError extends Error {
  constructor(
    public readonly vars: string[],
    context: string,
  ) {
    super(`Missing required configuration: ${vars.join(', ')}. ${context}`);
    this.name = 'MissingConfigError';
  }
}

function read(name: string): string | undefined {
  const value = process.env[name];
  return value && value.trim().length > 0 ? value : undefined;
}

export interface CloudflareApiConfig {
  apiToken: string;
  accountId: string;
}

export function getCloudflareApiConfig(): CloudflareApiConfig {
  const apiToken = read('CF_API_TOKEN');
  const accountId = read('CF_ACCOUNT_ID');
  const missing: string[] = [];
  if (!apiToken) missing.push('CF_API_TOKEN');
  if (!accountId) missing.push('CF_ACCOUNT_ID');
  if (missing.length > 0) {
    throw new MissingConfigError(
      missing,
      'Required for live Cloudflare API calls. Set them as Worker secrets/vars ' +
        '(or in .env for local runs).',
    );
  }
  return { apiToken: apiToken!, accountId: accountId! };
}

export interface SlackConfig {
  /** Empty string when unset — the channel is then not built at all and
   *  /channels/slack/* serves 503, so verification never runs. */
  signingSecret: string;
  botToken: string | undefined;
}

export function getSlackConfig(): SlackConfig {
  return {
    signingSecret: read('SLACK_SIGNING_SECRET') ?? '',
    botToken: read('SLACK_BOT_TOKEN'),
  };
}

export class MissingConfigError extends Error {
  constructor(
    public readonly vars: string[],
    context: string,
  ) {
    super(`Missing required configuration: ${vars.join(', ')}. ${context}`);
    this.name = 'MissingConfigError';
  }
}

export class InvalidConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidConfigError';
  }
}

function read(name: string): string | undefined {
  const value = process.env[name];
  return value && value.trim().length > 0 ? value : undefined;
}

// Local (`flue run`) needs a provider key (openai/gpt-4o + OPENAI_API_KEY);
// deployed uses cloudflare/openai/gpt-4o and routes through the AI binding.
export function getModel(): `${string}/${string}` {
  const raw = process.env.MODEL ?? 'openai/gpt-4o';
  if (!/^[^/]+\/.+$/.test(raw)) {
    throw new InvalidConfigError(
      `MODEL must be in "provider/model" form (e.g. "openai/gpt-4o"), got "${raw}".`,
    );
  }
  return raw as `${string}/${string}`;
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

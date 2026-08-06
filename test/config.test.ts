import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { getCloudflareApiConfig, getSlackConfig, MissingConfigError } from '../src/lib/config.ts';

// Config reads process.env at call time, so each test mutates a clean copy.
const CONFIG_VARS = ['CF_API_TOKEN', 'CF_ACCOUNT_ID', 'SLACK_SIGNING_SECRET', 'SLACK_BOT_TOKEN'];

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = {};
  for (const key of CONFIG_VARS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of CONFIG_VARS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

describe('getCloudflareApiConfig', () => {
  test('throws MissingConfigError listing every missing var', () => {
    try {
      getCloudflareApiConfig();
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(MissingConfigError);
      expect((err as MissingConfigError).vars).toEqual(['CF_API_TOKEN', 'CF_ACCOUNT_ID']);
    }
  });
  test('treats whitespace-only values as unset', () => {
    process.env.CF_API_TOKEN = '   ';
    process.env.CF_ACCOUNT_ID = 'acct123';
    expect(() => getCloudflareApiConfig()).toThrow(MissingConfigError);
  });
  test('returns config when both present', () => {
    process.env.CF_API_TOKEN = 'tok';
    process.env.CF_ACCOUNT_ID = 'acct123';
    expect(getCloudflareApiConfig()).toEqual({ apiToken: 'tok', accountId: 'acct123' });
  });
});

describe('getSlackConfig (fail closed)', () => {
  test('signingSecret is empty string when unset, botToken undefined', () => {
    expect(getSlackConfig()).toEqual({ signingSecret: '', botToken: undefined });
  });
  test('passes through configured values', () => {
    process.env.SLACK_SIGNING_SECRET = 'sekret';
    process.env.SLACK_BOT_TOKEN = 'xoxb-1';
    expect(getSlackConfig()).toEqual({ signingSecret: 'sekret', botToken: 'xoxb-1' });
  });
});

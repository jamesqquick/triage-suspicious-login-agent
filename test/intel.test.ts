import type Cloudflare from 'cloudflare';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { classify, getIndicatorIntel, type IntelEntry } from '../src/tools/intel.ts';
import { __setCloudflareClientForTests } from '../src/lib/cf-client.ts';

// RAW /intel/ip responses — arrays, as the SDK returns them.
const ipResponses: Record<string, unknown[]> = {
  '185.220.101.45': [
    {
      ip: '185.220.101.45',
      belongs_to_ref: {
        value: '24940',
        description: 'HETZNER-AS',
        country: 'DE',
        type: 'hosting_provider',
      },
      risk_types: [{ name: 'Anonymizer' }, { name: 'Botnet, Command and Control' }],
    },
  ],
  // 8.8.8.8: no intel record → empty array → lookup_failed (never "clean").
  '8.8.8.8': [],
};

// RAW /intel/domain responses — a single object, as the SDK returns.
const domainResponses: Record<string, unknown> = {
  'malware-c2-domain.ru': {
    domain: 'malware-c2-domain.ru',
    content_categories: [
      { id: 1, name: 'Malware' },
      { id: 2, name: 'Command and Control' },
    ],
    resolves_to_refs: [{ id: 'r1', value: '91.108.4.1' }],
    risk_score: 1,
    risk_types: [{ name: 'Malware' }],
  },
};

// Fake client exposing only the intel methods the tool calls.
const fakeClient = {
  intel: {
    ips: {
      get: async (params: { ipv4?: string; ipv6?: string }) =>
        ipResponses[params.ipv4 ?? params.ipv6 ?? ''] ?? [],
    },
    domains: {
      get: async (params: { domain?: string }) => {
        const hit = domainResponses[params.domain ?? ''];
        if (!hit) throw new Error('no such domain');
        return hit;
      },
    },
  },
} as unknown as Cloudflare;

describe('classify', () => {
  test('IPv4', () => {
    expect(classify('8.8.8.8')).toBe('ipv4');
    expect(classify('185.220.101.45')).toBe('ipv4');
  });
  test('rejects octets > 255 as non-IPv4', () => {
    expect(classify('999.1.1.1')).not.toBe('ipv4');
  });
  test('IPv6', () => {
    expect(classify('2001:db8::1')).toBe('ipv6');
  });
  test('domain', () => {
    expect(classify('malware-c2-domain.ru')).toBe('domain');
    expect(classify('example.com')).toBe('domain');
  });
  test('unknown for junk input', () => {
    expect(classify('not a valid indicator')).toBe('unknown');
  });
});

// run() returns a { output } envelope; unwrap and cast for assertions.
type IntelResult = Record<string, IntelEntry>;
const runIntel = async (indicators: string[]) =>
  (
    (await getIndicatorIntel.run({ data: { indicators } } as never)) as {
      output: IntelResult;
    }
  ).output;

describe('get_indicator_intel (injected client)', () => {
  const savedEnv: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const key of ['CF_API_TOKEN', 'CF_ACCOUNT_ID']) {
      savedEnv[key] = process.env[key];
    }
    process.env.CF_API_TOKEN = 'tok';
    process.env.CF_ACCOUNT_ID = 'acct123';
    __setCloudflareClientForTests(fakeClient);
  });
  afterEach(() => {
    __setCloudflareClientForTests(undefined);
    for (const key of ['CF_API_TOKEN', 'CF_ACCOUNT_ID']) {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    }
  });

  test('returns enriched threat entries for known indicators', async () => {
    const result = await runIntel(['185.220.101.45', 'malware-c2-domain.ru']);
    expect(result['185.220.101.45'].status).toBe('enriched');
    expect(result['185.220.101.45'].is_threat).toBe(true);
    expect(result['malware-c2-domain.ru'].is_threat).toBe(true);
  });

  test('unknown indicators are lookup_failed, never silently clean', async () => {
    const result = await runIntel(['8.8.8.8']); // valid IP, but no fixture entry
    expect(result['8.8.8.8'].status).toBe('lookup_failed');
    expect(result['8.8.8.8'].is_threat).toBe(false);
    expect(result['8.8.8.8'].error).toBeTruthy();
  });
});

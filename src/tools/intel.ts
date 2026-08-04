import { defineTool } from '@flue/runtime';
import * as v from 'valibot';
import { cfErrorNote, getCloudflareClient } from '../lib/cf-client.ts';
import { getCloudflareApiConfig } from '../lib/config.ts';
import { asJson } from '../lib/json.ts';

// Strict IPv4 (rejects 999.999.999.999). IPv6 is detected by structure.
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^(?=.*:)[0-9a-f:]+$/i;
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;

const THREAT_CATEGORY_KEYWORDS = [
  'malware',
  'phishing',
  'command and control',
  'spam',
  'botnet',
  'cryptomining',
  'spyware',
];

type IndicatorKind = 'ipv4' | 'ipv6' | 'domain' | 'unknown';

export function classify(indicator: string): IndicatorKind {
  if (IPV4_RE.test(indicator)) return 'ipv4';
  if (IPV6_RE.test(indicator)) return 'ipv6';
  if (DOMAIN_RE.test(indicator)) return 'domain';
  return 'unknown';
}

// Shapes mirror the documented v4 responses:
//   /intel/domain -> https://developers.cloudflare.com/api/resources/intel/subresources/domains/methods/get/
//   /intel/ip     -> https://developers.cloudflare.com/api/resources/intel/subresources/ips/methods/get/
interface RiskType {
  id?: number;
  name?: string;
  super_category_id?: number;
}

interface DomainIntelResult {
  domain: string;
  resolves_to_refs?: Array<{ id: string; value: string }>;
  application?: { id?: number; name?: string };
  content_categories?: Array<{
    id: number;
    name: string;
    super_category_id?: number;
  }>;
  risk_score?: number;
  risk_types?: RiskType[];
}

interface IPIntelResult {
  ip: string;
  belongs_to_ref?: {
    id?: string;
    value?: string;
    type?: string;
    country?: string;
    description?: string;
  };
  risk_types?: RiskType[] | null;
}

// lookup_failed: is_threat is false but MUST NOT be read as "clean" — the
// indicator could not be evaluated. Never silently dropped, so the gap is visible.
export type IntelStatus = 'enriched' | 'lookup_failed';

export type IntelEntry = {
  indicator: string;
  kind: 'ip' | 'domain' | 'unknown';
  status: IntelStatus;
  is_threat: boolean;
  error?: string;
  asn?: {
    number?: number;
    description?: string;
    country?: string;
    type?: string;
  };
  risk_types?: string[];
  content_categories?: string[];
  application?: string | null;
  resolves_to?: string[];
  risk_score?: number;
};

function failed(indicator: string, kind: IntelEntry['kind'], error: string): IntelEntry {
  return { indicator, kind, status: 'lookup_failed', is_threat: false, error };
}

function riskTypeNames(types: RiskType[] | null | undefined): string[] {
  return (types ?? [])
    .map((t) => t?.name)
    .filter((name): name is string => typeof name === 'string' && name.length > 0);
}

async function enrichIP(indicator: string, kind: IndicatorKind): Promise<IntelEntry> {
  const { accountId } = getCloudflareApiConfig();
  const params =
    kind === 'ipv6'
      ? { account_id: accountId, ipv6: indicator }
      : { account_id: accountId, ipv4: indicator };
  const raw = ((await getCloudflareClient().intel.ips.get(params)) ?? []) as IPIntelResult[];
  const entry = raw.find((r) => r.ip === indicator) ?? raw[0];
  if (!entry) return failed(indicator, 'ip', 'no intel record returned for indicator');
  const risk_types = riskTypeNames(entry.risk_types);
  const asNumber =
    entry.belongs_to_ref?.value !== undefined ? Number(entry.belongs_to_ref.value) : undefined;
  return {
    indicator,
    kind: 'ip',
    status: 'enriched',
    is_threat: risk_types.length > 0,
    asn: entry.belongs_to_ref
      ? {
          number: Number.isFinite(asNumber) ? asNumber : undefined,
          description: entry.belongs_to_ref.description,
          country: entry.belongs_to_ref.country,
          type: entry.belongs_to_ref.type,
        }
      : undefined,
    risk_types,
  };
}

async function enrichDomain(indicator: string): Promise<IntelEntry> {
  const { accountId } = getCloudflareApiConfig();
  const raw = (await getCloudflareClient().intel.domains.get({
    account_id: accountId,
    domain: indicator,
  })) as DomainIntelResult;
  const categoryNames = raw.content_categories?.map((c) => c.name) ?? [];
  const risk_types = riskTypeNames(raw.risk_types);
  // Threat if Cloudflare tagged a risk type, or a content category matches a
  // known-malicious keyword.
  const is_threat =
    risk_types.length > 0 ||
    categoryNames.some((name) =>
      THREAT_CATEGORY_KEYWORDS.some((kw) => name.toLowerCase().includes(kw)),
    );
  return {
    indicator,
    kind: 'domain',
    status: 'enriched',
    is_threat,
    content_categories: categoryNames,
    application: raw.application?.name ?? null,
    resolves_to: raw.resolves_to_refs?.map((r) => r.value),
    risk_score: raw.risk_score,
    risk_types: risk_types.length > 0 ? risk_types : undefined,
  };
}

async function enrichOne(indicator: string): Promise<IntelEntry> {
  const kind = classify(indicator);
  if (kind === 'unknown') {
    return failed(indicator, 'unknown', 'unrecognized indicator format (not an IP or domain)');
  }
  try {
    return kind === 'domain' ? await enrichDomain(indicator) : await enrichIP(indicator, kind);
  } catch (err) {
    // A failed lookup (including a 404) is reported, never treated as clean:
    // absence of a reputation record is not evidence the indicator is safe.
    const { note } = cfErrorNote(err);
    return failed(indicator, kind === 'domain' ? 'domain' : 'ip', note);
  }
}

export const getIndicatorIntel = defineTool({
  name: 'get_indicator_intel',
  description:
    'Enrich IP addresses and domains with Cloudflare Intelligence (Security Center) reputation data. ' +
    'Calls /intel/ip (ASN info + risk_types — non-empty risk_types means Cloudflare flagged the IP as malicious) ' +
    'and /intel/domain (content_categories, risk_types, resolved IPs, risk_score). ' +
    'Every indicator is returned with status "enriched" or "lookup_failed"; a lookup_failed entry means the ' +
    'indicator could NOT be evaluated and must not be treated as clean.',
  input: v.object({
    indicators: v.pipe(
      v.array(v.string()),
      v.description('IP addresses and/or domain names to enrich'),
    ),
  }),
  async run({ data }) {
    const entries = await Promise.all(data.indicators.map(enrichOne));
    const results: Record<string, IntelEntry> = {};
    for (const entry of entries) results[entry.indicator] = entry;
    return { output: asJson(results) };
  },
});

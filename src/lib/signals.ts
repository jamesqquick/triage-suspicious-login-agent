// Deterministic signal extraction for Access log records.
//
// Why this is code and not rubric prose: counting denials, enumerating distinct
// IPs, and bucketing timestamps are arithmetic over a JSON array. Asking the
// model to do it over ~300 records produces approximations — measured across 5
// identical runs it dropped 3-7 of 40 distinct IPs every time, never cited a
// denied record as the triggering event, and invented an off-hours correlation
// on a 14:00 UTC record. The model still writes the narrative and the
// recommendation; it no longer has to be a spreadsheet.

/** A denial burst needs at least this many denials from one IP. */
export const BURST_MIN_DENIALS = 3;
/** ...falling inside this window. 5 denials in 4m44s qualifies; isolated singles do not. */
export const BURST_WINDOW_SECONDS = 15 * 60;

// Off-hours is evaluated in UTC because Access logs are UTC and we do not know
// the user's local timezone. The field names say so, so a report cannot imply
// local-time knowledge it does not have.
export const OFF_HOURS_START_HOUR_UTC = 22;
export const OFF_HOURS_END_HOUR_UTC = 6;

export type RiskLevel = 'unknown' | 'low' | 'medium' | 'high' | 'critical';

/** Ordinal scale for the four scored levels. `unknown` is deliberately absent — it
 *  means "not assessable", which is not a point on a low..critical axis. */
export const RISK_RANK: Record<Exclude<RiskLevel, 'unknown'>, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** Structural subset of a Cloudflare Access request record. */
export interface AccessRecord {
  allowed?: boolean;
  app_domain?: string;
  ip_address?: string;
  created_at?: string;
  user_email?: string;
}

export interface DenialBurst {
  ip: string;
  count: number;
  windowSeconds: number;
  firstAt: string;
  lastAt: string;
}

export interface TriggeringEvent {
  user_email?: string;
  app_domain?: string;
  allowed?: boolean;
  ip_address?: string;
  created_at?: string;
  /** Why this record was selected, so the report can cite it honestly. */
  reason: string;
}

export interface Signals {
  totalRecords: number;
  deniedCount: number;
  allowedCount: number;
  distinctIps: string[];
  distinctIpCount: number;
  denialsByIp: Record<string, number>;
  denialBursts: DenialBurst[];
  offHoursUtcCount: number;
  offHoursUtcDeniedCount: number;
  /** Ready-to-quote phrasing. Composing this sentence is where the model invented a
   *  denial/off-hours correlation, so the correct wording is supplied rather than asked for. */
  offHoursSummary: string;
  triggeringEvent: TriggeringEvent | null;
  /** Set when the Access log query itself failed, so zero records is distinguishable
   *  from "the window was genuinely empty". Null on every successful fetch. */
  fetchError: string | null;
  riskFloor: RiskLevel;
  riskFloorReason: string;
}

function epochSeconds(iso: string | undefined): number | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

function utcHour(iso: string | undefined): number | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : new Date(ms).getUTCHours();
}

export function isOffHoursUtc(iso: string | undefined): boolean {
  const hour = utcHour(iso);
  if (hour === null) return false;
  return hour >= OFF_HOURS_START_HOUR_UTC || hour < OFF_HOURS_END_HOUR_UTC;
}

/**
 * Largest set of denials from one IP inside BURST_WINDOW_SECONDS, via a sliding
 * window over ascending timestamps. Returns null when the threshold is not met.
 */
function findBurst(ip: string, isoTimes: string[]): DenialBurst | null {
  const stamped = isoTimes
    .map((iso) => ({ iso, at: epochSeconds(iso) }))
    .filter((s): s is { iso: string; at: number } => s.at !== null)
    .sort((a, b) => a.at - b.at);
  if (stamped.length < BURST_MIN_DENIALS) return null;

  let best: DenialBurst | null = null;
  let start = 0;
  for (let end = 0; end < stamped.length; end += 1) {
    while (stamped[end].at - stamped[start].at > BURST_WINDOW_SECONDS) start += 1;
    const count = end - start + 1;
    if (count >= BURST_MIN_DENIALS && (best === null || count > best.count)) {
      best = {
        ip,
        count,
        windowSeconds: stamped[end].at - stamped[start].at,
        firstAt: stamped[start].iso,
        lastAt: stamped[end].iso,
      };
    }
  }
  return best;
}

/**
 * Selects the record a report should cite. Prefers the opening denial of the
 * largest burst, then the most recent denial, then the most recent record —
 * so `accessEvent` describes a denial whenever one exists.
 */
function selectTriggeringEvent(
  records: AccessRecord[],
  denials: AccessRecord[],
  bursts: DenialBurst[],
): TriggeringEvent | null {
  const describe = (r: AccessRecord, reason: string): TriggeringEvent => ({
    user_email: r.user_email,
    app_domain: r.app_domain,
    allowed: r.allowed,
    ip_address: r.ip_address,
    created_at: r.created_at,
    reason,
  });

  const topBurst = bursts[0];
  if (topBurst) {
    const opener = denials.find(
      (r) => r.ip_address === topBurst.ip && r.created_at === topBurst.firstAt,
    );
    if (opener) {
      return describe(
        opener,
        `first of ${topBurst.count} denials from ${topBurst.ip} within ${topBurst.windowSeconds}s`,
      );
    }
  }

  const byNewest = (a: AccessRecord, b: AccessRecord) =>
    (epochSeconds(b.created_at) ?? 0) - (epochSeconds(a.created_at) ?? 0);

  const newestDenial = [...denials].sort(byNewest)[0];
  if (newestDenial) return describe(newestDenial, 'most recent denied login');

  const newest = [...records].sort(byNewest)[0];
  if (newest) return describe(newest, 'most recent record; no denials in window');

  return null;
}

/**
 * Lower bound on risk from the log data alone.
 *
 * Repeated occurrences of one signal type count once — 5 denials from a single
 * IP is one high signal (denials present), not five, and a burst does not stack
 * on top of the denials it is made of. That keeps `critical` meaningful for
 * genuine threat-intel hits instead of firing on every brute-force attempt.
 *
 * Intel-derived signals are not visible here, so this is a floor only: intel
 * (`is_threat: true`) can raise the verdict, never lower it.
 */
function computeRiskFloor(signals: {
  totalRecords: number;
  deniedCount: number;
  denialBursts: DenialBurst[];
  offHoursUtcCount: number;
  fetchError: string | null;
}): { riskFloor: RiskLevel; riskFloorReason: string } {
  // Checked before totalRecords, because a failed fetch also yields zero records
  // and the two must not be reported as the same thing: "no logins found" would
  // be a factual claim about the account that was never actually established.
  if (signals.fetchError) {
    return {
      riskFloor: 'unknown',
      riskFloorReason: `the Access log query failed (${signals.fetchError}) — no records were read, so nothing about this user has been assessed`,
    };
  }
  if (signals.totalRecords === 0) {
    return {
      riskFloor: 'unknown',
      riskFloorReason:
        'no records returned for the window — absence of logs is a coverage gap, not evidence of safety',
    };
  }
  if (signals.deniedCount > 0) {
    const burst = signals.denialBursts[0];
    const detail = burst
      ? `, including ${burst.count} from ${burst.ip} within ${burst.windowSeconds}s`
      : '';
    return {
      riskFloor: 'high',
      riskFloorReason: `${signals.deniedCount} denied login record(s)${detail} — denied logins are a High signal`,
    };
  }
  if (signals.offHoursUtcCount > 0) {
    return {
      riskFloor: 'medium',
      riskFloorReason: `${signals.offHoursUtcCount} login(s) outside ${OFF_HOURS_END_HOUR_UTC}:00-${OFF_HOURS_START_HOUR_UTC}:00 UTC and no denials — off-hours access is a Medium signal`,
    };
  }
  return {
    riskFloor: 'low',
    riskFloorReason: 'no denied logins and no off-hours access in the window',
  };
}

/**
 * @param fetchError Non-null when the Access log query failed. Callers pass the
 *   error instead of throwing, so the failure arrives as data the rubric already
 *   scores (`unknown`) rather than as a tool error the model has no rule for.
 */
export function computeSignals(records: AccessRecord[], fetchError: string | null = null): Signals {
  const denials = records.filter((r) => r.allowed === false);

  const distinctIps: string[] = [];
  const seen = new Set<string>();
  for (const r of records) {
    const ip = r.ip_address;
    if (!ip || seen.has(ip)) continue;
    seen.add(ip);
    distinctIps.push(ip);
  }

  const denialTimesByIp = new Map<string, string[]>();
  const denialsByIp: Record<string, number> = {};
  for (const r of denials) {
    const ip = r.ip_address;
    if (!ip) continue;
    denialsByIp[ip] = (denialsByIp[ip] ?? 0) + 1;
    const times = denialTimesByIp.get(ip);
    if (times) times.push(r.created_at ?? '');
    else denialTimesByIp.set(ip, [r.created_at ?? '']);
  }

  const denialBursts: DenialBurst[] = [];
  for (const [ip, times] of denialTimesByIp) {
    const burst = findBurst(ip, times);
    if (burst) denialBursts.push(burst);
  }
  denialBursts.sort((a, b) => b.count - a.count || a.windowSeconds - b.windowSeconds);

  const offHours = records.filter((r) => isOffHoursUtc(r.created_at));
  const offHoursUtcCount = offHours.length;
  const offHoursUtcDeniedCount = offHours.filter((r) => r.allowed === false).length;
  const window = `${OFF_HOURS_END_HOUR_UTC}:00-${OFF_HOURS_START_HOUR_UTC}:00 UTC`;
  const offHoursSummary =
    offHoursUtcCount === 0
      ? `no logins outside ${window}`
      : offHoursUtcDeniedCount === 0
        ? `${offHoursUtcCount} login(s) outside ${window}, none of them denied`
        : `${offHoursUtcCount} login(s) outside ${window}, ${offHoursUtcDeniedCount} of them denied`;

  const { riskFloor, riskFloorReason } = computeRiskFloor({
    totalRecords: records.length,
    deniedCount: denials.length,
    denialBursts,
    offHoursUtcCount,
    fetchError,
  });

  return {
    totalRecords: records.length,
    deniedCount: denials.length,
    allowedCount: records.filter((r) => r.allowed === true).length,
    distinctIps,
    distinctIpCount: distinctIps.length,
    denialsByIp,
    denialBursts,
    offHoursUtcCount,
    offHoursUtcDeniedCount,
    offHoursSummary,
    triggeringEvent: selectTriggeringEvent(records, denials, denialBursts),
    fetchError,
    riskFloor,
    riskFloorReason,
  };
}

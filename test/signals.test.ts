import { describe, expect, test } from 'vitest';
import { type AccessRecord, computeSignals, isOffHoursUtc } from '../src/lib/signals.ts';

// Mirrors the shape of the alice@skyflash.co fixture the lab uses: 11 denials,
// 5 of them from one IP inside 4m44s, and off-hours records that are all allowed.
const denialBurstIp = '2a02:a44f:6e80:0:f14e:4faf:a7d1:9c57';

function rec(over: Partial<AccessRecord>): AccessRecord {
  return {
    user_email: 'alice@skyflash.co',
    app_domain: 'wiki.skyflash.co',
    allowed: true,
    ip_address: '10.0.0.1',
    created_at: '2026-07-21T12:00:00Z',
    ...over,
  };
}

const burst: AccessRecord[] = [
  rec({ allowed: false, ip_address: denialBurstIp, created_at: '2026-07-21T09:03:13Z' }),
  rec({ allowed: false, ip_address: denialBurstIp, created_at: '2026-07-21T09:03:38Z' }),
  rec({ allowed: false, ip_address: denialBurstIp, created_at: '2026-07-21T09:03:50Z' }),
  rec({ allowed: false, ip_address: denialBurstIp, created_at: '2026-07-21T09:04:09Z' }),
  rec({ allowed: false, ip_address: denialBurstIp, created_at: '2026-07-21T09:07:57Z' }),
];

describe('isOffHoursUtc', () => {
  test('flags before 06:00 and at/after 22:00 UTC', () => {
    expect(isOffHoursUtc('2026-07-21T03:00:00Z')).toBe(true);
    expect(isOffHoursUtc('2026-07-21T23:30:00Z')).toBe(true);
    expect(isOffHoursUtc('2026-07-21T22:00:00Z')).toBe(true);
  });
  test('does not flag mid-afternoon — the record the model kept mislabeling', () => {
    expect(isOffHoursUtc('2026-07-21T14:10:48Z')).toBe(false);
  });
  test('unparseable or missing timestamps are not off-hours', () => {
    expect(isOffHoursUtc(undefined)).toBe(false);
    expect(isOffHoursUtc('not-a-date')).toBe(false);
  });
});

describe('computeSignals counting', () => {
  test('counts denials and enumerates every distinct IP', () => {
    const s = computeSignals([
      ...burst,
      rec({ ip_address: '1.1.1.1' }),
      rec({ ip_address: '2.2.2.2' }),
      rec({ ip_address: '1.1.1.1' }),
    ]);
    expect(s.totalRecords).toBe(8);
    expect(s.deniedCount).toBe(5);
    expect(s.allowedCount).toBe(3);
    expect(s.distinctIps).toEqual([denialBurstIp, '1.1.1.1', '2.2.2.2']);
    expect(s.distinctIpCount).toBe(3);
  });

  test('records with no ip_address do not create an empty indicator', () => {
    const s = computeSignals([rec({ ip_address: undefined }), rec({ ip_address: '1.1.1.1' })]);
    expect(s.distinctIps).toEqual(['1.1.1.1']);
  });

  test('denialsByIp is per-IP', () => {
    const s = computeSignals([...burst, rec({ allowed: false, ip_address: '9.9.9.9' })]);
    expect(s.denialsByIp).toEqual({ [denialBurstIp]: 5, '9.9.9.9': 1 });
  });
});

describe('computeSignals denial bursts', () => {
  test('detects 5 denials inside a 15 minute window', () => {
    const s = computeSignals(burst);
    expect(s.denialBursts).toHaveLength(1);
    expect(s.denialBursts[0]).toMatchObject({
      ip: denialBurstIp,
      count: 5,
      firstAt: '2026-07-21T09:03:13Z',
      lastAt: '2026-07-21T09:07:57Z',
    });
    expect(s.denialBursts[0].windowSeconds).toBe(284);
  });

  test('two isolated denials from one IP are not a burst', () => {
    const s = computeSignals([
      rec({ allowed: false, ip_address: '5.5.5.5', created_at: '2026-07-10T15:50:00Z' }),
      rec({ allowed: false, ip_address: '5.5.5.5', created_at: '2026-07-10T15:50:37Z' }),
    ]);
    expect(s.denialBursts).toEqual([]);
    expect(s.riskFloor).toBe('high');
  });

  test('three denials spread beyond the window are not a burst', () => {
    const s = computeSignals([
      rec({ allowed: false, ip_address: '5.5.5.5', created_at: '2026-07-10T10:00:00Z' }),
      rec({ allowed: false, ip_address: '5.5.5.5', created_at: '2026-07-10T10:20:00Z' }),
      rec({ allowed: false, ip_address: '5.5.5.5', created_at: '2026-07-10T10:40:00Z' }),
    ]);
    expect(s.denialBursts).toEqual([]);
  });

  test('denials from different IPs do not combine into one burst', () => {
    const s = computeSignals([
      rec({ allowed: false, ip_address: 'a', created_at: '2026-07-10T10:00:00Z' }),
      rec({ allowed: false, ip_address: 'b', created_at: '2026-07-10T10:00:10Z' }),
      rec({ allowed: false, ip_address: 'c', created_at: '2026-07-10T10:00:20Z' }),
    ]);
    expect(s.denialBursts).toEqual([]);
  });

  test('largest burst is first', () => {
    const s = computeSignals([
      ...burst,
      rec({ allowed: false, ip_address: 'x', created_at: '2026-07-11T10:00:00Z' }),
      rec({ allowed: false, ip_address: 'x', created_at: '2026-07-11T10:00:10Z' }),
      rec({ allowed: false, ip_address: 'x', created_at: '2026-07-11T10:00:20Z' }),
    ]);
    expect(s.denialBursts.map((b) => b.count)).toEqual([5, 3]);
  });
});

describe('computeSignals off-hours', () => {
  test('separates off-hours volume from off-hours denials', () => {
    const s = computeSignals([
      rec({ created_at: '2026-07-21T03:00:00Z' }),
      rec({ created_at: '2026-07-21T23:00:00Z' }),
      rec({ allowed: false, created_at: '2026-07-21T14:10:48Z' }),
    ]);
    expect(s.offHoursUtcCount).toBe(2);
    // The fabricated finding this exists to prevent: the denial is at 14:00.
    expect(s.offHoursUtcDeniedCount).toBe(0);
  });
});

describe('computeSignals triggeringEvent', () => {
  test('cites the opening denial of the largest burst', () => {
    const s = computeSignals([...burst, rec({ ip_address: '1.1.1.1' })]);
    expect(s.triggeringEvent?.allowed).toBe(false);
    expect(s.triggeringEvent?.created_at).toBe('2026-07-21T09:03:13Z');
    expect(s.triggeringEvent?.reason).toContain('5 denials');
  });

  test('falls back to the most recent denial when there is no burst', () => {
    const s = computeSignals([
      rec({ allowed: false, ip_address: '5.5.5.5', created_at: '2026-07-10T10:00:00Z' }),
      rec({ allowed: false, ip_address: '6.6.6.6', created_at: '2026-07-12T10:00:00Z' }),
      rec({ created_at: '2026-07-20T10:00:00Z' }),
    ]);
    expect(s.triggeringEvent?.allowed).toBe(false);
    expect(s.triggeringEvent?.created_at).toBe('2026-07-12T10:00:00Z');
  });

  test('never prefers an allowed record while a denial exists', () => {
    const s = computeSignals([
      rec({ created_at: '2026-08-04T12:00:00Z' }), // newest, allowed
      rec({ allowed: false, created_at: '2026-07-01T12:00:00Z' }),
    ]);
    expect(s.triggeringEvent?.allowed).toBe(false);
  });

  test('uses the most recent record when there are no denials', () => {
    const s = computeSignals([
      rec({ created_at: '2026-07-01T12:00:00Z' }),
      rec({ created_at: '2026-07-09T12:00:00Z' }),
    ]);
    expect(s.triggeringEvent?.created_at).toBe('2026-07-09T12:00:00Z');
    expect(s.triggeringEvent?.reason).toContain('no denials');
  });

  test('is null for an empty record set', () => {
    expect(computeSignals([]).triggeringEvent).toBeNull();
  });
});

describe('computeSignals riskFloor', () => {
  test('no records is unknown, not low', () => {
    const s = computeSignals([]);
    expect(s.riskFloor).toBe('unknown');
    expect(s.riskFloorReason).toContain('coverage gap');
  });

  test('any denial floors at high', () => {
    expect(computeSignals([rec({ allowed: false })]).riskFloor).toBe('high');
  });

  test('a burst still floors at high, not critical', () => {
    // Bursts are made of denials, so they are one High signal, not two.
    expect(computeSignals(burst).riskFloor).toBe('high');
  });

  test('off-hours without denials floors at medium', () => {
    const s = computeSignals([rec({ created_at: '2026-07-21T03:00:00Z' })]);
    expect(s.riskFloor).toBe('medium');
  });

  test('clean activity floors at low', () => {
    const s = computeSignals([rec({ created_at: '2026-07-21T14:00:00Z' })]);
    expect(s.riskFloor).toBe('low');
  });

  test('the floor reason states the denial count', () => {
    expect(computeSignals(burst).riskFloorReason).toContain('5 denied login record');
  });
});

describe('computeSignals offHoursSummary', () => {
  test('states explicitly that no off-hours login was denied', () => {
    const s = computeSignals([
      rec({ created_at: '2026-07-21T03:00:00Z' }),
      rec({ allowed: false, created_at: '2026-07-21T14:10:48Z' }),
    ]);
    expect(s.offHoursSummary).toBe('1 login(s) outside 6:00-22:00 UTC, none of them denied');
  });
  test('reports the denied subset when there is one', () => {
    const s = computeSignals([rec({ allowed: false, created_at: '2026-07-21T03:00:00Z' })]);
    expect(s.offHoursSummary).toBe('1 login(s) outside 6:00-22:00 UTC, 1 of them denied');
  });
  test('says so when there is no off-hours access at all', () => {
    const s = computeSignals([rec({ created_at: '2026-07-21T14:00:00Z' })]);
    expect(s.offHoursSummary).toBe('no logins outside 6:00-22:00 UTC');
  });
});

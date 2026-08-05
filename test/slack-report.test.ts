import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
  applyRiskFloor,
  buildBlocks,
  createTriageReportTool,
  formatReport,
} from '../src/tools/slack-report.ts';

const report = {
  riskLevel: 'critical' as const,
  summary: 'Denied Access attempts from a flagged anonymizer IP',
  keyFindings: ['4 denied logins in 6 minutes', 'Source IP on a Cloudflare threat list'],
  accessEvent: 'employee@company.com denied at app.company.com from 185.220.101.45',
  threatIntelHits: ['185.220.101.45 — risk_types: Anonymizer, Botnet'],
  recommendedAction: 'Rotate credentials & block the source ASN',
};

describe('formatReport', () => {
  test('includes the uppercased risk level and findings', () => {
    const text = formatReport(report);
    expect(text).toContain('risk: CRITICAL');
    expect(text).toContain('4 denied logins in 6 minutes');
  });
  test('renders "(none)" for empty lists', () => {
    const text = formatReport({ ...report, threatIntelHits: [] });
    expect(text).toContain('(none)');
  });
});

describe('buildBlocks', () => {
  test('header carries the risk emoji and level', () => {
    const blocks = buildBlocks(report) as Array<Record<string, any>>;
    expect(blocks[0].type).toBe('header');
    expect(blocks[0].text.text).toContain('CRITICAL');
    expect(blocks[0].text.text).toContain('\u{1F534}');
  });
  test('renders the access event section', () => {
    const blocks = buildBlocks(report) as Array<Record<string, any>>;
    const eventBlock = blocks.find((b) => b.text?.text?.includes('Access event'));
    expect(eventBlock?.text.text).toContain('185.220.101.45');
  });
  test('escapes mrkdwn control characters', () => {
    const blocks = buildBlocks({ ...report, summary: 'a < b & c > d' }) as Array<
      Record<string, any>
    >;
    const summaryBlock = blocks.find((b) => b.text?.text?.includes('Summary'));
    expect(summaryBlock?.text.text).toContain('&lt;');
    expect(summaryBlock?.text.text).toContain('&amp;');
    expect(summaryBlock?.text.text).toContain('&gt;');
  });
});

// ToolContext stand-in: step.do runs inline (no interruption), log is a no-op.
function runCtx(data: typeof report) {
  return {
    data,
    step: { do: <T,>(_name: string, fn: () => T | Promise<T>) => Promise.resolve(fn()) },
    log: { info() {}, warn() {}, error() {} },
  } as never;
}

describe('createTriageReportTool delivery', () => {
  const SLACK_VARS = ['SLACK_BOT_TOKEN'];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = {};
    for (const key of SLACK_VARS) {
      saved[key] = process.env[key];
      delete process.env[key];
    }
  });
  afterEach(() => {
    for (const key of SLACK_VARS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });

  test('no Slack thread -> delivered to run output', async () => {
    const tool = createTriageReportTool();
    const { output: result } = (await tool.run(runCtx(report))) as {
      output: { delivered: string; riskLevel: string };
    };
    expect(result.delivered).toBe('run-output');
    expect(result.riskLevel).toBe('critical');
  });

  test('Slack thread but no bot token -> delivered:"failed" (never a false success)', async () => {
    const tool = createTriageReportTool({ channelId: 'C123', threadTs: '111.222' } as never);
    const { output: result } = (await tool.run(runCtx(report))) as {
      output: { delivered: string; error?: string };
    };
    expect(result.delivered).toBe('failed');
    expect(result.error).toMatch(/SLACK_BOT_TOKEN/);
  });
});

describe('applyRiskFloor', () => {
  const base = { ...report, riskFloor: 'high' as const };

  test('raises an under-scored verdict to the floor and flags it', () => {
    // The measured 1-in-5 failure: `medium` returned on a 5-denial burst.
    const out = applyRiskFloor({ ...base, riskLevel: 'medium', riskFloor: 'high' });
    expect(out.riskLevel).toBe('high');
    expect(out.escalatedByPolicy).toBe(true);
  });

  test('leaves a verdict at the floor untouched', () => {
    const out = applyRiskFloor({ ...base, riskLevel: 'high', riskFloor: 'high' });
    expect(out.riskLevel).toBe('high');
    expect(out.escalatedByPolicy).toBe(false);
  });

  test('allows scoring above the floor when intel adds a critical signal', () => {
    const out = applyRiskFloor({ ...base, riskLevel: 'critical', riskFloor: 'high' });
    expect(out.riskLevel).toBe('critical');
    expect(out.escalatedByPolicy).toBe(false);
  });

  test('an unknown floor forces unknown — no records means no verdict', () => {
    // The measured zero-data failure: scored `low` while saying logs were missing.
    const out = applyRiskFloor({ ...base, riskLevel: 'low', riskFloor: 'unknown' });
    expect(out.riskLevel).toBe('unknown');
    expect(out.escalatedByPolicy).toBe(true);
  });

  test('unknown floor with an unknown verdict is not an escalation', () => {
    const out = applyRiskFloor({ ...base, riskLevel: 'unknown', riskFloor: 'unknown' });
    expect(out.riskLevel).toBe('unknown');
    expect(out.escalatedByPolicy).toBe(false);
  });

  test('unknown verdict against a real floor is raised to the floor', () => {
    const out = applyRiskFloor({ ...base, riskLevel: 'unknown', riskFloor: 'medium' });
    expect(out.riskLevel).toBe('medium');
    expect(out.escalatedByPolicy).toBe(true);
  });

  test('riskFloor is not rendered into the report body', () => {
    const out = applyRiskFloor({ ...base, riskLevel: 'high', riskFloor: 'high' });
    expect(out).not.toHaveProperty('riskFloor');
  });
});

describe('escalation is visible in the rendered report', () => {
  test('formatReport notes a policy-set level', () => {
    const text = formatReport({ ...report, escalatedByPolicy: true });
    expect(text).toContain('policy floor');
  });
  test('formatReport stays clean when the model agreed with the floor', () => {
    expect(formatReport({ ...report, escalatedByPolicy: false })).not.toContain('policy floor');
  });
  test('buildBlocks surfaces the escalation notice', () => {
    const blocks = buildBlocks({ ...report, escalatedByPolicy: true }) as Array<
      Record<string, any>
    >;
    const notice = blocks.find((b) => b.elements?.[0]?.text?.includes('policy floor'));
    expect(notice).toBeDefined();
  });
  test('unknown risk level renders', () => {
    const text = formatReport({ ...report, riskLevel: 'unknown' });
    expect(text).toContain('risk: UNKNOWN');
  });
});

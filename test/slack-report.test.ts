import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { buildBlocks, createTriageReportTool, formatReport } from '../src/tools/slack-report.ts';

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

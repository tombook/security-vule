import { describe, expect, test } from 'bun:test';
import { buildStarMapData, buildRadarData, generateHTMLReport } from '../../../src/visualization/html-report.js';
import type { VuleReport } from '../../../src/engine/vule-report.js';

const sampleReport: VuleReport = {
  version: '0.3.0',
  generatedAt: '2026-06-10T00:00:00Z',
  nodeCount: 2,
  riskDistribution: { LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 1 } as any,
  topRisk: [
    { nodeId: 'n2', file: 'a.php', line: 2, code: 'mysql_query($q)', uvrs: 0.9, level: 'CRITICAL' as any, dominantDimension: 'gravity', contributions: { gravity: 0.8, kepler: 0.5 } },
    { nodeId: 'n1', file: 'a.php', line: 1, code: '$_GET["x"]', uvrs: 0.1, level: 'LOW' as any, dominantDimension: 'ast', contributions: { ast: 0.1 } },
  ],
};

describe('HTML report data builders', () => {
  test('buildStarMapData returns nodes + edges arrays', () => {
    const data = buildStarMapData(sampleReport);
    expect(data.nodes).toHaveLength(2);
    expect(Array.isArray(data.edges)).toBe(true);
    expect(data.nodes[0].level).toBe('CRITICAL');
  });
  test('buildRadarData returns dimensions + values', () => {
    const radar = buildRadarData(sampleReport.topRisk[0]);
    expect(radar.dimensions.length).toBeGreaterThan(0);
    expect(radar.values.length).toBe(radar.dimensions.length);
  });
  test('generateHTMLReport includes D3 + Plotly + report data', () => {
    const html = generateHTMLReport(sampleReport);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('cdn.jsdelivr.net/npm/d3@7');
    expect(html).toContain('cdn.plot.ly');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('mysql_query');
  });
  test('handles empty topRisk gracefully', () => {
    const empty: VuleReport = { ...sampleReport, topRisk: [] };
    const html = generateHTMLReport(empty);
    expect(html).toContain('Top Risk Nodes');
    expect(html).not.toContain('undefined');
  });
});
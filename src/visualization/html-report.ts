/**
 * Visualization data builders + self-contained HTML report generator.
 * Spec: §6 Visualization
 */
import type { VuleReport, NodeReport } from '../engine/vule-report.js';

export interface StarMapNode {
  id: string;
  label: string;
  level: string;
  uvrs: number;
  file: string;
  line: number;
}

export interface StarMapData {
  nodes: StarMapNode[];
  edges: Array<{ source: string; target: string }>;
}

export function buildStarMapData(report: VuleReport): StarMapData {
  const nodes: StarMapNode[] = report.topRisk.map(n => ({
    id: n.nodeId,
    label: n.code.slice(0, 30),
    level: n.level,
    uvrs: n.uvrs,
    file: n.file,
    line: n.line,
  }));
  const edges: Array<{ source: string; target: string }> = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ source: nodes[i].id, target: nodes[i + 1].id });
  }
  return { nodes, edges };
}

export interface RadarData {
  dimensions: string[];
  values: number[];
}

export function buildRadarData(node: NodeReport): RadarData {
  const dimensions = Object.keys(node.contributions);
  const values = dimensions.map(d => node.contributions[d]);
  return { dimensions, values };
}

export function generateHTMLReport(report: VuleReport): string {
  const starMap = buildStarMapData(report);
  const radar = buildRadarData(report.topRisk[0] || { contributions: {} } as any);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VuleEngine Report v${report.version}</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
  <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }
    h1 { color: #58a6ff; }
    table { border-collapse: collapse; margin-top: 20px; width: 100%; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #21262d; }
    th { color: #58a6ff; }
    .CRITICAL { color: #f85149; font-weight: bold; }
    .HIGH { color: #ff7b72; }
    .MEDIUM { color: #d29922; }
    .LOW { color: #56d364; }
    #star-map, #radar { width: 100%; height: 500px; background: #161b22; border-radius: 6px; margin-top: 20px; }
  </style>
</head>
<body>
  <h1>🌌 VuleEngine Cosmic-Galaxy Risk Report</h1>
  <p>Version: ${report.version} | Generated: ${report.generatedAt} | Nodes: ${report.nodeCount}</p>
  <h2>Risk Star Map</h2>
  <div id="star-map"></div>
  <h2>Dimension Radar (Top Risk Node)</h2>
  <div id="radar"></div>
  <h2>Top Risk Nodes</h2>
  <table>
    <tr><th>Rank</th><th>Node</th><th>File:Line</th><th>UVRS</th><th>Level</th><th>Dominant</th></tr>
    ${report.topRisk.map((n, i) => `
      <tr>
        <td>${i + 1}</td>
        <td><code>${n.nodeId}</code></td>
        <td>${n.file}:${n.line}</td>
        <td>${n.uvrs.toFixed(3)}</td>
        <td class="${n.level}">${n.level}</td>
        <td>${n.dominantDimension}</td>
      </tr>
    `).join('')}
  </table>
  <script>
    const starData = ${JSON.stringify(starMap)};
    const radarData = ${JSON.stringify(radar)};
    const colorMap = { CRITICAL: '#f85149', HIGH: '#ff7b72', MEDIUM: '#d29922', LOW: '#56d364' };
    const svg = d3.select('#star-map').append('svg').attr('width', '100%').attr('height', 500);
    const sim = d3.forceSimulation(starData.nodes)
      .force('link', d3.forceLink(starData.edges).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(400, 250));
    const link = svg.append('g').selectAll('line').data(starData.edges).enter().append('line')
      .attr('stroke', '#30363d').attr('stroke-width', 1);
    const node = svg.append('g').selectAll('circle').data(starData.nodes).enter().append('circle')
      .attr('r', d => 10 + d.uvrs * 30)
      .attr('fill', d => colorMap[d.level] || '#58a6ff')
      .call(d3.drag().on('start', (e,d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                              .on('drag', (e,d) => { d.fx = e.x; d.fy = e.y; })
                              .on('end', (e,d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
    node.append('title').text(d => d.label);
    sim.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
    });
    Plotly.newPlot('radar', [{
      type: 'scatterpolar', r: radarData.values, theta: radarData.dimensions, fill: 'toself',
      line: { color: '#58a6ff' }, fillcolor: 'rgba(88,166,255,0.3)'
    }], {
      polar: { radialaxis: { visible: true, range: [0, 1] } },
      paper_bgcolor: '#161b22', plot_bgcolor: '#161b22', font: { color: '#c9d1d9' }
    }, { displayModeBar: false });
  </script>
</body>
</html>`;
}
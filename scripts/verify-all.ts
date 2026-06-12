import { VuleSandboxBridge } from '../src/poc/vule-sandbox-bridge.js';
import { PAYLOAD_DATABASE } from '../src/poc/payload-database.js';

const bridge = new VuleSandboxBridge({ targets: ['dvwa', 'bwapp', 'sqlilabs', 'pikachu'] });

console.log('Running verification against all payloads...\n');
const verifications = await bridge.verifyAll();

const report = bridge.generateReport(verifications);

console.log(`Total: ${report.totalVulns}`);
console.log(`Verified: ${report.verifiedVulns}/${report.totalVulns} (${(report.verificationRate * 100).toFixed(1)}%)`);
console.log(`\nUVRS Distribution: ${JSON.stringify(report.uvrsDistribution)}`);

const targetMap: Record<string, {total: number, verified: number}> = {};
for (const v of verifications) {
  if (!targetMap[v.target]) targetMap[v.target] = {total: 0, verified: 0};
  targetMap[v.target].total++;
  if (v.verified) targetMap[v.target].verified++;
}
console.log('\nPer-target breakdown:');
for (const [t, s] of Object.entries(targetMap).sort()) {
  console.log(`  ${t}: ${s.verified}/${s.total} (${(s.verified/s.total*100).toFixed(1)}%)`);
}

const typeMap: Record<string, {total: number, verified: number}> = {};
for (const v of verifications) {
  if (!typeMap[v.vulnType]) typeMap[v.vulnType] = {total: 0, verified: 0};
  typeMap[v.vulnType].total++;
  if (v.verified) typeMap[v.vulnType].verified++;
}
console.log('\nPer-type breakdown:');
for (const [t, s] of Object.entries(typeMap).sort((a,b) => b[1].total - a[1].total)) {
  console.log(`  ${t}: ${s.verified}/${s.total} (${(s.verified/s.total*100).toFixed(0)}%)`);
}

const failed = verifications.filter(v => !v.verified);
if (failed.length > 0) {
  console.log('\nFailed verifications:');
  for (const f of failed) {
    console.log(`  ${f.id} (${f.target}/${f.vulnType}): status=${f.bestResult?.status ?? 'no_result'}`);
  }
}

const jsonReport = {
  generatedAt: report.generatedAt,
  totalVulns: report.totalVulns,
  verifiedVulns: report.verifiedVulns,
  verificationRate: report.verificationRate,
  uvrsDistribution: report.uvrsDistribution,
  byTarget: targetMap,
  byType: typeMap,
  failedIds: failed.map(f => ({id: f.id, target: f.target, type: f.vulnType, status: f.bestResult?.status ?? 'no_result'})),
  allResults: verifications.map(v => ({
    id: v.id, target: v.target, type: v.vulnType,
    verified: v.verified, confidence: Number(v.confidence.toFixed(3)),
    status: v.bestResult?.status ?? 'no_result'
  }))
};
await Bun.write('/tmp/vule-verification-report.json', JSON.stringify(jsonReport, null, 2));
console.log('\nFull report written to /tmp/vule-verification-report.json');

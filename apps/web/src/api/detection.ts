// apps/web/src/api/detection.ts
// Client for /provider/v1/detection/* — the Detection Center UI.
//
// All four tool-call endpoints added in commit 73... (this batch) are
// exposed here so the Vue view can call them without inlining axios.
import { apiClient } from './client';

export interface Engine {
  id: string;
  name: string;
  engineType: string;
  version: string;
  enabled: boolean;
  healthStatus: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastHealthCheckAt: string | null;
  config: Record<string, unknown>;
  createdAt: string;
  /** null for the global built-ins (semgrep / trivy / …); tenant id for per-tenant engines */
  tenantId: string | null;
}

export interface Rule {
  id: string;
  externalId: string;
  title: string;
  description: string | null;
  severity: string;
  cweIds: string[];
  owaspIds: string[];
  defaultEnabled: boolean;
  engineName: string;
  engineType: string;
}

export interface PolicyConfig {
  id: string;
  scope: 'tenant' | 'customer' | 'project';
  customerId: string | null;
  projectId: string | null;
  name: string;
  enabledEngines: string[];
  enabledRules: string[];
  severityThreshold: string;
  incrementalMode: 'full' | 'incremental' | 'diff_only';
  autoScanOnSync: boolean;
  scanScheduleCron: string | null;
  includePaths: string[];
  excludePaths: string[];
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface QueueItem {
  id: string;
  projectId: string;
  projectName: string | null;
  customerId: string;
  customerName: string | null;
  policyVersionId: string | null;
  triggerType: 'manual' | 'scheduled' | 'webhook' | 'api';
  incrementalMode: string;
  status: 'queued' | 'running' | 'analyzing' | 'done' | 'partial' | 'failed' | 'canceled';
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingsTotal: number;
  findingsNew: number;
  findingsFixed: number;
  errorMessage: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface HealthCheckResult {
  id: string;
  healthStatus: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  latencyMs: number;
  checkedAt: string;
}

export interface TriggerScanResult {
  id: string;
  status: string;
  created_at: string;
}

const BASE = '/provider/v1/detection';

// ── Reads (already wired before this commit) ─────────────────────────────
export async function listEngines(): Promise<{ items: Engine[] }> {
  const { data } = await apiClient.get(`${BASE}/engines`);
  return data;
}

export async function listRules(engine?: string, q?: string): Promise<{ items: Rule[] }> {
  const { data } = await apiClient.get(`${BASE}/rules`, {
    params: { engine, q },
  });
  return data;
}

export async function listPolicies(): Promise<{ items: PolicyConfig[] }> {
  const { data } = await apiClient.get(`${BASE}/policies`);
  return data;
}

export async function listQueue(status = 'all'): Promise<{ items: QueueItem[] }> {
  const { data } = await apiClient.get(`${BASE}/queue`, { params: { status } });
  return data;
}

// ── Tool-call endpoints (added this batch) ───────────────────────────────
export async function toggleEngine(id: string, enabled: boolean): Promise<{ id: string; enabled: boolean }> {
  const { data } = await apiClient.patch(`${BASE}/engines/${id}`, { enabled });
  return data;
}

export async function healthCheck(id: string): Promise<HealthCheckResult> {
  const { data } = await apiClient.post(`${BASE}/engines/${id}/health-check`, {});
  return data;
}

export async function syncEngine(id: string): Promise<{ engineId: string; rulesTouched: number }> {
  const { data } = await apiClient.post(`${BASE}/engines/${id}/sync`, {});
  return data;
}

export async function triggerScan(body: { projectId: string; incremental?: boolean }): Promise<TriggerScanResult> {
  const { data } = await apiClient.post(`${BASE}/scans/trigger`, body);
  return data;
}

export async function cancelScan(id: string): Promise<{ id: string; status: string }> {
  const { data } = await apiClient.post(`${BASE}/queue/${id}/cancel`, {});
  return data;
}

// ── Vulnerability detection capabilities catalogue ──────────────────
// White-box patterns (kind=static) + LLM-augmented analyses
// (kind=llm) + runtime verification probes (kind=runtime). Mirrors
// apps/api/src/routes/detection.ts /capabilities.
export type CapabilityKind = 'static' | 'llm' | 'runtime';

export interface Capability {
  kind: CapabilityKind;
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe: string;
  owasp: string;
  langs: string[];
  description: string;
  // Per-tenant enable state. For kind=static this is persisted
  // (detection.tenant_capabilities); for kind=llm and kind=runtime
  // it's always true (platform-wide, not user-toggleable).
  enabled: boolean;
}
export async function listCapabilities(): Promise<{ capabilities: Capability[] }> {
  const { data } = await apiClient.get(`${BASE}/capabilities`);
  return data;
}

export async function toggleCapability(
  id: string,
  enabled: boolean,
): Promise<{ id: string; enabled: boolean }> {
  const { data } = await apiClient.patch<{ id: string; enabled: boolean }>(
    `${BASE}/capabilities/${id}`,
    { enabled },
  );
  return data;
}

// ── Project-level detection roll-up ─────────────────────────────────
export interface ProjectDetectionRow {
  customer_id: string;
  customer_name: string;
  project_id: string;
  project_name: string;
  project_status: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open_critical: number;
  open_high: number;
  open_medium: number;
  last_finding_at: string;
}
export async function listProjectDetections(): Promise<{ items: ProjectDetectionRow[] }> {
  const { data } = await apiClient.get(`${BASE}/projects`);
  return data;
}

// ── LLM usage roll-up (workflows.md §3) ────────────────────────────
export interface UsageBucket {
  capability?: string;
  provider?: string;
  model?: string;
  calls: number;
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  cost_usd: number;
}
export interface UsageReport {
  since: string;
  total: UsageBucket;
  byCapability: UsageBucket[];
  byProvider: UsageBucket[];
}
export async function getLlmUsage(since = '30d'): Promise<UsageReport> {
  const { data } = await apiClient.get<UsageReport>(`${BASE}/usage`, { params: { since } });
  return data;
}
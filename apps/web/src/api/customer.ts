import { apiClient } from './client';

export interface CustomerDashboard {
  kpis: {
    criticalFindings: number;
    highFindings: number;
    confirmedExploits: number;
    recentScans: number;
  };
  recentFindings: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    filePath: string;
    lastSeenAt: string;
  }>;
}

export interface CustomerProject {
  id: string;
  name: string;
  slug: string;
  status: string;
  slaTier: string;
  defaultBranch: string | null;
  totalScans: number;
  lastScanAt: string | null;
  openFindings: number;
  createdAt: string;
}

export interface CustomerProjectDetail extends CustomerProject {
  description: string | null;
  branchPolicy: any;
  dataRetentionDays: number;
  totalFindings: number;
  scans: Array<{
    id: string;
    trigger_type: string;
    status: string;
    started_at: string;
    finished_at: string;
    duration_ms: number;
    findings_total: number;
    findings_new: number;
    findings_fixed: number;
  }>;
}

export interface CustomerFinding {
  id: string;
  title: string;
  severity: string;
  status: string;
  filePath: string;
  startLine: number;
  endLine: number;
  cweIds: string[];
  firstSeenAt: string;
  lastSeenAt: string;
  projectName: string | null;
  hasPocProof: boolean;
}

export interface CustomerFindingDetail extends CustomerFinding {
  description: string | null;
  codeSnippet: string | null;
  owaspIds: string[];
  confidence: string;
  engines: string[];
  dfgPath: any;
  confirmedAt: string | null;
  fixedAt: string | null;
  projectId: string;
  ruleTitle: string | null;
  ruleDescription: string | null;
  stateHistory: any[];
  pocRuns: any[];
  comments: any[];
}

export interface CustomerReport {
  id: string;
  reportType: string;
  format: string;
  periodStart: string | null;
  periodEnd: string | null;
  fileSizeBytes: string | null;
  status: string;
  createdAt: string;
}

export interface CustomerUsage {
  totals: { eventCount: number; totalTokens: number; totalCost: number };
  byCapability: Array<{ capability: string; tokens: number }>;
  byDay: Array<{ day: string; tokens: number }>;
  quota: { plan: string; monthlyTokenQuota: number; balanceUsd: number } | null;
}

export interface CustomerMember {
  id: string;
  email: string;
  fullName: string | null;
  role: string;
  status: string;
  lastLoginAt: string | null;
}

export const CUSTOMER_BASE = '/customer/v1';

export async function getDashboard(): Promise<CustomerDashboard> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/dashboard`);
  return data;
}

export async function listProjects(): Promise<{ items: CustomerProject[] }> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/projects`);
  return data;
}

export async function getProject(id: string): Promise<CustomerProjectDetail> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/projects/${id}`);
  return data;
}

export async function listFindings(params: { severity?: string; status?: string; project_id?: string } = {}): Promise<{ items: CustomerFinding[] }> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/findings`, { params });
  return data;
}

export async function getFinding(id: string): Promise<CustomerFindingDetail> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/findings/${id}`);
  return data;
}

export async function listReports(): Promise<{ items: CustomerReport[] }> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/reports`);
  return data;
}

export async function getUsage(): Promise<CustomerUsage> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/usage`);
  return data;
}

export async function getMembers(): Promise<{ members: CustomerMember[]; pendingInvites: any[] }> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/settings/members`);
  return data;
}

export async function getIntegrations(): Promise<{ webhooks: any[]; ticketIntegrations: any[] }> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/settings/integrations`);
  return data;
}

export async function getNotificationPrefs(): Promise<any> {
  const { data } = await apiClient.get(`${CUSTOMER_BASE}/settings/notifications`);
  return data;
}

export async function saveNotificationPrefs(prefs: any): Promise<{ ok: boolean }> {
  const { data } = await apiClient.put(`${CUSTOMER_BASE}/settings/notifications`, prefs);
  return data;
}

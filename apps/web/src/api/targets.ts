// apps/web/src/api/targets.ts
//
// Client for /provider/v1/targets. The list endpoint is open to any
// role in the tenant; create / patch / delete require a write role.
import { apiClient } from './client';

export interface Target {
  id: string;
  tenant_id: string;
  customer_id: string;
  project_id: string | null;
  customer_name?: string;
  name: string;
  base_url: string;
  target_type: 'http' | 'https' | 'docker' | 'ssh' | 'mock';
  auth_kind: 'none' | 'basic' | 'form' | 'cookie' | 'bearer' | 'header';
  auth_username?: string | null;
  cookie_jar?: Record<string, string>;
  allow_insecure?: boolean;
  status: 'active' | 'paused' | 'broken' | 'retired';
  last_seen_at?: string | null;
  last_health?: string | null;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface CreateTargetInput {
  customerId: string;
  projectId?: string;
  name: string;
  baseUrl: string;
  targetType?: Target['target_type'];
  authKind?: Target['auth_kind'];
  authUsername?: string;
  authPassword?: string;
  authToken?: string;
  cookieJar?: Record<string, string>;
  allowInsecure?: boolean;
  metadata?: Record<string, any>;
}

export async function listTargets(params: { customerId?: string; status?: string } = {}): Promise<{ items: Target[] }> {
  const { data } = await apiClient.get<{ items: Target[] }>('/provider/v1/targets', { params });
  return data;
}

export async function getTarget(id: string): Promise<Target> {
  const { data } = await apiClient.get<Target>(`/provider/v1/targets/${id}`);
  return data;
}

export async function createTarget(input: CreateTargetInput): Promise<Target> {
  const { data } = await apiClient.post<Target>('/provider/v1/targets', input);
  return data;
}

export async function patchTarget(id: string, input: Partial<CreateTargetInput>): Promise<Target> {
  const { data } = await apiClient.patch<Target>(`/provider/v1/targets/${id}`, input);
  return data;
}

export async function deleteTarget(id: string): Promise<{ deleted: { id: string; status: string } }> {
  const { data } = await apiClient.delete<{ deleted: { id: string; status: string } }>(`/provider/v1/targets/${id}`);
  return data;
}

export interface HealthProbeResult {
  ok: boolean;
  httpStatus: number;
  latencyMs: number;
  detail: string;
}

export async function probeTarget(id: string): Promise<HealthProbeResult> {
  const { data } = await apiClient.post<HealthProbeResult>(`/provider/v1/targets/${id}/health`);
  return data;
}
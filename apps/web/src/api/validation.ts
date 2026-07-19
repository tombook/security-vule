import { apiClient } from './client';

export interface PocRun {
  id: string;
  status: 'pending' | 'approved' | 'running' | 'success' | 'failed' | 'timeout' | 'canceled';
  source: 'ai' | 'manual' | 'library_reuse';
  pocScript: string;
  pocScriptHash: string;
  exploitProven: boolean;
  approvedBy: string | null;
  approvedAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  exitCode: number | null;
  stdoutLog: string | null;
  stderrLog: string | null;
  behaviorReport: any;
  evidenceUrl: string | null;
  errorMessage: string | null;
  createdAt: string;
  updatedAt: string;
  finding: {
    id: string;
    title: string;
    severity: string;
    file: string;
    line: number;
  };
}

export interface PocLibraryItem {
  id: string;
  title: string;
  description: string | null;
  language: string;
  framework_tags: string[];
  cwe_ids: string[];
  reuse_count: number;
  last_reused_at: string | null;
  created_at: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
  createdAt: string;
  promptTokens: number;
  completionTokens: number;
}

export interface GenerateResult {
  id: string;
  status: string;
  reused?: boolean;
  category?: string;
  script?: string;
  rationale?: string;
  successIndicators?: string[];
  createdAt?: string;
  usage?: { promptTokens: number; completionTokens: number; costUsd: number };
}

export interface ExecutionResult {
  status: 'success' | 'failed' | 'timeout' | 'error';
  exitCode: number;
  stdoutLog: string;
  stderrLog: string;
  behaviorReport: {
    actions: string[];
    networkCalls: string[];
    filesAccessed: string[];
    durationMs: number;
  };
  exploitProven: boolean;
  evidenceSummary: string;
}

export async function listQueue(status = 'all'): Promise<{ items: PocRun[] }> {
  const { data } = await apiClient.get<{ items: PocRun[] }>('/provider/v1/validation/queue', {
    params: { status },
  });
  return data;
}

export async function getPocRun(id: string): Promise<PocRun> {
  const { data } = await apiClient.get<PocRun>(`/provider/v1/validation/poc/${id}`);
  return data;
}

export async function generatePoc(findingId: string): Promise<GenerateResult> {
  const { data } = await apiClient.post<GenerateResult>('/provider/v1/validation/poc/generate', {
    findingId,
  });
  return data;
}

export async function approvePoc(id: string, comment?: string): Promise<{ id: string; status: string; approved_at: string }> {
  const { data } = await apiClient.post(`/provider/v1/validation/poc/${id}/approve`, { comment });
  return data;
}

export async function rejectPoc(id: string, reason: string): Promise<{ id: string; status: string }> {
  const { data } = await apiClient.post(`/provider/v1/validation/poc/${id}/reject`, { reason });
  return data;
}

export async function executePoc(id: string): Promise<ExecutionResult> {
  const { data } = await apiClient.post<ExecutionResult>(`/provider/v1/validation/poc/${id}/execute`);
  return data;
}

export async function listChatMessages(pocRunId: string): Promise<{ items: ChatMessage[] }> {
  const { data } = await apiClient.get<{ items: ChatMessage[] }>(`/provider/v1/validation/poc/${pocRunId}/chat`);
  return data;
}

export async function postChatMessage(pocRunId: string, message: string): Promise<{ user: ChatMessage; assistant: ChatMessage }> {
  const { data } = await apiClient.post(`/provider/v1/validation/poc/${pocRunId}/chat`, { message });
  return data;
}

export async function listLibrary(): Promise<{ items: PocLibraryItem[] }> {
  const { data } = await apiClient.get<{ items: PocLibraryItem[] }>('/provider/v1/validation/library');
  return data;
}

export async function addToLibrary(pocRunId: string, title: string, description?: string, cweIds: string[] = []): Promise<PocLibraryItem> {
  const { data } = await apiClient.post<PocLibraryItem>('/provider/v1/validation/library', {
    pocRunId,
    title,
    description,
    cweIds,
  });
  return data;
}

import { apiClient } from './client';

export interface ScanProject {
  id: string;
  name: string;
  slug: string;
  status: string;
  description?: string;
  defaultBranch: string;
  createdAt: string;
}

export interface ScanSource {
  id: string;
  projectId: string;
  sourceType: string;
  repoFullName: string | null;
  branch: string;
  status: string;
  lastSyncedAt: string | null;
}

export interface ScanRun {
  id: string;
  projectId: string;
  status: 'queued' | 'running' | 'analyzing' | 'done' | 'partial' | 'failed' | 'canceled';
  triggerType: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingsTotal: number;
  findingsNew: number;
  findingsFixed: number;
  errorMessage: string | null;
  createdAt: string;
}

const BASE = '/provider/v1/scan';

export async function createProject(body: { customerId: string; name: string; description?: string; defaultBranch?: string }): Promise<ScanProject> {
  const { data } = await apiClient.post<ScanProject>(`${BASE}/projects`, body);
  return data;
}

export async function configureProject(id: string): Promise<{ id: string; status: string }> {
  const { data } = await apiClient.post(`${BASE}/projects/${id}/configure`, {});
  return data;
}

export async function connectSource(body: { projectId: string; sourceType: 'github' | 'gitlab' | 'upload'; repoFullName?: string; repoUrl?: string; branch?: string }): Promise<ScanSource> {
  const { data } = await apiClient.post<ScanSource>(`${BASE}/sources`, body);
  return data;
}

export async function syncSource(id: string): Promise<any> {
  const { data } = await apiClient.post(`${BASE}/sources/${id}/sync`, {});
  return data;
}

export async function triggerScan(body: { projectId: string; triggerType?: 'manual' | 'ci' | 'poll' | 'policy_change' }): Promise<ScanRun> {
  const { data } = await apiClient.post<ScanRun>(`${BASE}/scans/trigger`, body);
  return data;
}

export async function getScan(id: string): Promise<ScanRun> {
  const { data } = await apiClient.get<ScanRun>(`${BASE}/scans/${id}`);
  return data;
}

export async function listProjects(params: { customerId?: string; status?: string } = {}): Promise<{ items: ScanProject[] }> {
  const { data } = await apiClient.get<{ items: ScanProject[] }>(`${BASE}/projects`, { params });
  return data;
}

export async function getProject(id: string): Promise<any> {
  const { data } = await apiClient.get<any>(`${BASE}/projects/${id}`);
  return data;
}

export async function deleteProject(id: string): Promise<{ ok: boolean; deleted: { id: string; name: string } }> {
  const { data } = await apiClient.delete<{ ok: boolean; deleted: { id: string; name: string } }>(`${BASE}/projects/${id}`);
  return data;
}

export async function getProjectSource(projectId: string): Promise<{ source: ScanSource | null; recentSyncs?: any[] }> {
  const { data } = await apiClient.get(`${BASE}/projects/${projectId}/source`);
  return data;
}

// ── Upload (zip → extracted source tree) ───────────────────────────
// Multipart upload because we send binary; axios auto-detects
// FormData and uses the browser's multipart encoder. The browser
// also handles large files in chunks so we don't blow the heap.
export interface UploadSourceResult {
  id: string;
  project_id: string;
  source_type: 'upload';
  branch: string;
  status: string;
  last_synced_at: string;
  upload_size_bytes: string;
  upload_object_key: string;
  upload: {
    rootPath: string;
    fileCount: number;
    sizeBytes: number;
    sample: string[];
  };
}

export async function uploadSource(projectId: string, file: File, branch = 'main'): Promise<UploadSourceResult> {
  // 先尝试 multipart 上传，如果后端环境不支持则回退到 base64 JSON
  try {
    const fd = new FormData();
    fd.append('projectId', projectId);
    fd.append('branch', branch);
    fd.append('file', file);
    const { data } = await apiClient.post<UploadSourceResult>(`${BASE}/sources`, fd, { timeout: 30000 });
    return data;
  } catch (multipartErr: any) {
    // multipart 失败（Bun 兼容性问题或超时），回退到 base64 JSON 方式
    const fileBuffer = await file.arrayBuffer();
    const fileBase64 = btoa(String.fromCharCode(...new Uint8Array(fileBuffer)));
    const { data } = await apiClient.post<UploadSourceResult>(`${BASE}/sources`, {
      sourceType: 'upload',
      projectId,
      branch,
      fileName: file.name,
      fileBase64,
    }, { timeout: 30000 });
    return data;
  }
}

export interface SourceFileList {
  sourceId: string;
  rootPath: string;
  fileCount: number;
  files: string[];
}

export async function listSourceFiles(sourceId: string): Promise<SourceFileList> {
  const { data } = await apiClient.get<SourceFileList>(`${BASE}/sources/${sourceId}/files`);
  return data;
}

export interface SourceFileRaw {
  path: string;
  content: string | null;
  size: number;
  note?: string;
}

export async function readSourceFile(sourceId: string, filePath: string): Promise<SourceFileRaw> {
  const { data } = await apiClient.get<SourceFileRaw>(`${BASE}/sources/${sourceId}/raw`, { params: { path: filePath } });
  return data;
}

export async function deleteSource(projectId: string): Promise<any> {
  const { data } = await apiClient.delete(`${BASE}/projects/${projectId}/source`);
  return data;
}

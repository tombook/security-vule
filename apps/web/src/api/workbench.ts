import { apiClient } from './client';

export interface KpiItem {
  key: string;
  label: string;
  value: number | string;
  unit?: string;
  change_pct?: number;
  change?: string;
  secondary?: string;
  badge?: string;
  action: string;
}

export interface WorkbenchOverview {
  kpis: KpiItem[];
  top_customers: any[];
  refreshed_at: string;
}

export async function getOverview(): Promise<WorkbenchOverview> {
  const { data } = await apiClient.get<WorkbenchOverview>('/provider/v1/workbench/overview');
  return data;
}

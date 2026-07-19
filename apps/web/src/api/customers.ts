import { apiClient } from './client';

export interface Customer {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'suspended' | 'deleted';
  contact_email: string | null;
  contact_phone: string | null;
  industry: string | null;
  sla_tier: string;
  white_label: any;
  created_at: string;
}

export interface CustomerList {
  items: Customer[];
  total: number;
  page: number;
  size: number;
}

export interface CreateCustomerInput {
  name: string;
  /** Optional — auto-generated from name (slugified) when omitted */
  slug?: string;
  contactEmail?: string;
  contactPhone?: string;
  industry?: string;
  /** 'standard' | 'priority' | 'premium' (default 'standard') */
  slaTier?: 'standard' | 'priority' | 'premium';
}

export interface CreateCustomerResult extends Customer {
  billing: {
    id: string;
    plan: string;
    monthly_token_quota: number;
    balance_usd: string;
    status: string;
  };
}

export async function listCustomers(params: { page?: number; size?: number; q?: string; status?: string } = {}): Promise<CustomerList> {
  const { data } = await apiClient.get<CustomerList>('/provider/v1/customers', { params });
  return data;
}

export async function getCustomer(id: string): Promise<Customer> {
  const { data } = await apiClient.get<Customer>(`/provider/v1/customers/${id}`);
  return data;
}

export async function createCustomer(input: CreateCustomerInput): Promise<CreateCustomerResult> {
  const { data } = await apiClient.post<CreateCustomerResult>('/provider/v1/customers', input);
  return data;
}

export interface DeleteCustomerResult {
  ok: boolean;
  deleted: { id: string; name: string };
  cascade: { projects_paused: boolean; targets_retired: boolean };
}

export async function deleteCustomer(id: string): Promise<DeleteCustomerResult> {
  const { data } = await apiClient.delete<DeleteCustomerResult>(`/provider/v1/customers/${id}`);
  return data;
}

export async function patchCustomer(id: string, body: Partial<CreateCustomerInput & { status: 'active' | 'suspended' }>): Promise<Customer> {
  const { data } = await apiClient.patch<Customer>(`/provider/v1/customers/${id}`, body);
  return data;
}

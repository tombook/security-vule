import { apiClient } from './client';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  tenant_id: string;
  portal: string;
  customer_id?: string;
}

export interface LoginResponse {
  access_token: string;
  user: User;
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/auth/login', { email, password });
  return data;
}

export async function getMe(): Promise<User> {
  const { data } = await apiClient.get<User>('/auth/me');
  return data;
}

export async function logout(): Promise<void> {
  await apiClient.post('/auth/logout');
}

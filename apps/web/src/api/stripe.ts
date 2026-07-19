import { apiClient } from './client';

export interface CheckoutResult {
  checkoutId: string;
  url: string;
  signature: string;
  demoNote: string;
}

export interface SubscriptionStatus {
  subscription: {
    plan: string;
    status: string;
    monthlyTokenQuota: number;
    balanceUsd: number;
    currentPeriodStart: string;
    currentPeriodEnd: string;
  } | null;
}

export interface Invoice {
  id: string;
  invoiceNumber: string;
  subtotalUsd: number;
  taxUsd: number;
  totalUsd: number;
  status: string;
  issuedAt: string | null;
  paidAt: string | null;
  periodStart: string | null;
  periodEnd: string | null;
}

const BASE = '/provider/v1/billing/stripe';

export async function createCheckout(plan: string, successUrl: string, cancelUrl: string): Promise<CheckoutResult> {
  const { data } = await apiClient.post<CheckoutResult>(`${BASE}/checkout`, {
    plan, success_url: successUrl, cancel_url: cancelUrl,
  });
  return data;
}

export async function mockConfirm(sessionId: string, tenantId: string, plan: string): Promise<{ ok: boolean }> {
  const { data } = await apiClient.post(`${BASE}/mock-confirm`, { sessionId, tenantId, plan });
  return data;
}

export async function getPortalUrl(returnUrl: string): Promise<{ url: string }> {
  const { data } = await apiClient.post(`${BASE}/portal`, { return_url: returnUrl });
  return data;
}

export async function getSubscription(): Promise<SubscriptionStatus> {
  const { data } = await apiClient.get<SubscriptionStatus>(`${BASE}/subscription`);
  return data;
}

export async function getInvoices(): Promise<{ items: Invoice[] }> {
  const { data } = await apiClient.get<{ items: Invoice[] }>(`${BASE}/invoices`);
  return data;
}

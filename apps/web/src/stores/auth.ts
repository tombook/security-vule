import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import * as authApi from '@/api/auth';
import type { User } from '@/api/auth';

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem('access_token'));
  const user = ref<User | null>(null);

  const isAuthenticated = computed(() => !!token.value);
  const role = computed(() => user.value?.role || '');
  const tenantId = computed(() => user.value?.tenant_id || '');

  async function login(email: string, password: string) {
    const res = await authApi.login(email, password);
    token.value = res.access_token;
    user.value = res.user;
    localStorage.setItem('access_token', res.access_token);
    return res;
  }

  const portal = computed(() => user.value?.portal ?? '');

  async function fetchMe() {
    user.value = await authApi.getMe();
  }

  function logout() {
    token.value = null;
    user.value = null;
    localStorage.removeItem('access_token');
  }

  return { token, user, isAuthenticated, role, tenantId, portal, login, fetchMe, logout };
});

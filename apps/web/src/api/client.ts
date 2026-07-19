import axios from 'axios';
import { ElMessage } from 'element-plus';

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '/api',
  timeout: 15000,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    } else {
      const msg = err.response?.data?.error?.message || err.message || '网络错误';
      ElMessage.error(msg);
    }
    return Promise.reject(err);
  },
);

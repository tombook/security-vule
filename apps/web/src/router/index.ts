import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      component: () => import('@/views/auth/LoginView.vue'),
      meta: { public: true, title: '登录' },
    },
    {
      path: '/sso/callback',
      component: () => import('@/views/auth/SsoCallbackView.vue'),
      meta: { public: true, title: 'SSO 回调' },
    },
    {
      path: '/sso/error',
      component: () => import('@/views/auth/SsoErrorView.vue'),
      meta: { public: true, title: 'SSO 错误' },
    },
    {
      path: '/apply',
      component: () => import('@/views/onboarding/ApplyView.vue'),
      meta: { public: true, title: '申请入驻' },
    },
    {
      path: '/forgot',
      component: () => import('@/views/auth/ForgotView.vue'),
      meta: { public: true, title: '忘记密码' },
    },
    {
      path: '/reset',
      component: () => import('@/views/auth/ResetView.vue'),
      meta: { public: true, title: '重置密码' },
    },
    {
      path: '/invite',
      component: () => import('@/views/auth/InviteView.vue'),
      meta: { public: true, title: '接受邀请' },
    },
    {
      path: '/oauth/callback',
      component: () => import('@/views/oauth/OAuthCallbackView.vue'),
      meta: { public: true, title: 'OAuth 回调' },
    },
    {
      path: '/',
      component: () => import('@/layouts/AppShell.vue'),
      redirect: '/',
      children: [
        {
          path: '',
          component: () => import('@/views/workbench/WorkbenchView.vue'),
          meta: { title: '工作台' },
        },
        {
          path: 'customers',
          component: () => import('@/views/customers/CustomersView.vue'),
          meta: { title: '客户' },
        },
        {
          path: 'customers/:id',
          component: () => import('@/views/customers/CustomerDetailView.vue'),
          meta: { title: '客户详情' },
        },
        {
          path: 'validation',
          component: () => import('@/views/validation/QueueView.vue'),
          meta: { title: 'PoC 验证' },
        },
        {
          path: 'validation/library',
          component: () => import('@/views/validation/LibraryView.vue'),
          meta: { title: 'PoC 库' },
        },
        {
          path: 'validation/poc/:id',
          component: () => import('@/views/validation/PocDetailView.vue'),
          meta: { title: 'PoC 详情' },
        },
        {
          path: 'detection',
          component: () => import('@/views/detection/DetectionView.vue'),
          meta: { title: '检测中心' },
        },
        {
          path: 'billing',
          component: () => import('@/views/billing/BillingView.vue'),
          meta: { title: '计费' },
        },
        {
          path: 'governance',
          component: () => import('@/views/governance/GovernanceView.vue'),
          meta: { title: '治理' },
        },
        {
          path: 'settings',
          component: () => import('@/views/settings/SettingsView.vue'),
          meta: { title: '设置' },
        },
        {
          path: 'projects/new',
          component: () => import('@/views/projects/NewProjectView.vue'),
          meta: { title: '新建项目' },
        },
        {
          path: 'projects/:id',
          component: () => import('@/views/projects/ProjectDetailView.vue'),
          meta: { title: '项目详情' },
        },
        {
          path: 'findings',
          component: () => import('@/views/findings/FindingsView.vue'),
          meta: { title: '漏洞' },
        },
        {
          path: 'findings/:id',
          component: () => import('@/views/findings/FindingDetailView.vue'),
          meta: { title: '漏洞详情' },
        },
        {
          path: 'sources',
          component: () => import('@/views/sources/SourcesView.vue'),
          meta: { title: '代码源' },
        },
        {
          path: 'sources/manage',
          component: () => import('@/views/sources/SourceManageView.vue'),
          meta: { title: '代码源管理' },
        },
        {
          path: 'targets',
          component: () => import('@/views/targets/TargetsView.vue'),
          meta: { title: '目标管理' },
        },
        {
          path: 'billing/success',
          component: () => import('@/views/billing/BillingSuccessView.vue'),
          meta: { title: '支付成功' },
        },
        {
          path: 'billing/cancel',
          component: () => import('@/views/billing/BillingCancelView.vue'),
          meta: { title: '已取消' },
        },
      ],
    },
    {
      path: '/portal',
      component: () => import('@/layouts/PortalShell.vue'),
      children: [
        {
          path: '',
          component: () => import('@/views/customer/DashboardView.vue'),
          meta: { title: '首页' },
        },
        {
          path: 'projects',
          component: () => import('@/views/customer/ProjectsView.vue'),
          meta: { title: '项目' },
        },
        {
          path: 'projects/:id',
          component: () => import('@/views/customer/ProjectDetailView.vue'),
          meta: { title: '项目详情' },
        },
        {
          path: 'findings',
          component: () => import('@/views/customer/FindingsView.vue'),
          meta: { title: '漏洞' },
        },
        {
          path: 'findings/:id',
          component: () => import('@/views/customer/FindingDetailView.vue'),
          meta: { title: '漏洞详情' },
        },
        {
          path: 'reports',
          component: () => import('@/views/customer/ReportsView.vue'),
          meta: { title: '报告' },
        },
        {
          path: 'usage',
          component: () => import('@/views/customer/UsageView.vue'),
          meta: { title: '用量' },
        },
        {
          path: 'settings',
          component: () => import('@/views/customer/CustomerSettingsView.vue'),
          meta: { title: '设置' },
        },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  if (to.meta.public) return true;
  if (!auth.isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } };
  }
  if (!auth.user) {
    try { await auth.fetchMe(); } catch { auth.logout(); return { path: '/login' }; }
  }
  return true;
});

export default router;

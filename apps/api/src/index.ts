import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger as honoLogger } from 'hono/logger';
import { config } from './config';
import { errorMiddleware } from './middleware/error';
import { authMiddleware } from './middleware/auth';
import { tenantMiddleware } from './middleware/tenant';
import { authRoutes } from './routes/auth';
import { workbenchRoutes } from './routes/workbench';
import { customerRoutes } from './routes/customers';
import { healthRoute } from './routes/health';
import { validationRoutes } from './routes/validation';
import { detectionRoutes } from './routes/detection';
import { billingRoutes } from './routes/billing';
import { governanceRoutes, gdprRoutes } from './routes/governance';
import { settingsRoutes } from './routes/settings';
import { customerRoutes as customerPortalRoutes } from './routes/customer';
import { stripeRoutes } from './routes/stripe';
import { scanRoutes } from './routes/scans';
import { whitelabelRoutes } from './routes/whitelabel';
import { customerWhitelabelRoutes } from './routes/customer-whitelabel';
import { ssoRoutes, ssoPublicRoutes } from './routes/sso';
import { mockIdpRoutes } from './routes/mock-idp';
import { oauthRoutes, onboardingRoutes } from './routes/oauth';
import { findingsRoutes } from './routes/findings';
import { ticketIntegrationsRoutes } from './routes/tickets';
import { usageRoutes } from './routes/usage';
import { reportsRoutes } from './routes/reports';
import { webhooksRoutes } from './routes/webhooks';
import { governancePermsRoutes } from './routes/governance-extras';
import { targetRoutes } from './routes/targets';
import { startMonthlyBillingWorker } from './workers/billing';

const app = new Hono();

app.use('*', honoLogger());
app.use('*', cors({
  origin: config.frontendUrl,
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

app.onError(errorMiddleware);

app.route('/api/health', healthRoute);

app.route('/api/auth', authRoutes);
app.route('/api/auth/sso', ssoPublicRoutes);
app.route('/mock-idp', mockIdpRoutes);
app.route('/api/onboarding', onboardingRoutes);

app.use('/api/provider/*', authMiddleware);
app.use('/api/customer/*', authMiddleware);
app.use('/api/provider/*', tenantMiddleware);
app.use('/api/customer/*', tenantMiddleware);
app.use('/api/provider/*', async (c, next) => {
  if (c.get('user').portal !== 'provider') {
    return c.json({ error: { code: 'wrong_portal', message: 'Provider portal required' } }, 403);
  }
  await next();
});
app.use('/api/customer/*', async (c, next) => {
  if (c.get('user').portal !== 'customer') {
    return c.json({ error: { code: 'wrong_portal', message: 'Customer portal required' } }, 403);
  }
  await next();
});
app.route('/api/provider/v1/workbench', workbenchRoutes);
app.route('/api/provider/v1/customers', customerRoutes);
app.route('/api/provider/v1/validation', validationRoutes);
app.route('/api/provider/v1/detection', detectionRoutes);
app.route('/api/provider/v1/billing', billingRoutes);
app.route('/api/provider/v1/governance', governanceRoutes);
app.route('/api/provider/v1/governance', gdprRoutes);
app.route('/api/provider/v1/settings', settingsRoutes);
app.route('/api/provider/v1/sso', ssoRoutes);
app.route('/api/provider/v1/oauth', oauthRoutes);
app.route('/api/customer/v1', customerPortalRoutes);
app.route('/api/customer/v1/whitelabel', customerWhitelabelRoutes);
app.route('/api/provider/v1/whitelabel', whitelabelRoutes);
app.route('/api/provider/v1/billing/stripe', stripeRoutes);
app.route('/api/provider/v1/scan', scanRoutes);
app.route('/api/provider/v1/targets', targetRoutes);
app.route('/api/provider/v1/findings', findingsRoutes);
app.route('/api/provider/v1/integrations/tickets', ticketIntegrationsRoutes);
app.route('/api/provider/v1/usage', usageRoutes);
app.route('/api/customer/v1/usage', usageRoutes);
app.route('/api/provider/v1/reports', reportsRoutes);
app.route('/api/customer/v1/reports', reportsRoutes);
app.route('/api/provider/v1/webhooks', webhooksRoutes);
app.route('/api/provider/v1/governance', governancePermsRoutes);

startMonthlyBillingWorker();

console.log(`[api] starting on http://localhost:${config.port}`);

export default {
  port: config.port,
  // Long-running endpoints (e.g. sandbox deploy that shells out
  // to `docker build` for large PHP / Node projects) need more
  // than the 10-second Bun.serve default. Bumped to 4 minutes
  // — Bun caps idleTimeout at 255, so 240 is the practical max.
  idleTimeout: 240,
  fetch: app.fetch,
};

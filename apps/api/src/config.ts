import 'dotenv/config';

function required(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  databaseUrl: required('DATABASE_URL', 'postgres://security_vule:dev_password@localhost:5432/security_vule'),
  jwtSecret: required('JWT_SECRET', 'dev-only-jwt-secret-please-change-in-prod-must-be-32-chars'),
  jwtAccessTtl: Number(process.env.JWT_ACCESS_TTL ?? 1800),
  logLevel: process.env.LOG_LEVEL ?? 'info',
  nodeEnv: process.env.NODE_ENV ?? 'development',
  frontendUrl: process.env.FRONTEND_URL ?? 'http://localhost:5173',
};

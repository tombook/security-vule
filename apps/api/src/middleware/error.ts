import type { Context } from 'hono';
import { ZodError } from 'zod';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

export const errorMiddleware = (err: Error, c: Context) => {
  if (err instanceof ZodError) {
    return c.json(
      { error: { code: 'validation_error', message: 'Invalid request', details: err.flatten() } },
      400,
    );
  }

  if (err instanceof ApiError) {
    return c.json(
      { error: { code: err.code, message: err.message, details: err.details } },
      err.status as 400 | 401 | 403 | 404 | 409 | 422 | 423 | 500,
    );
  }

  console.error('[api] unhandled error:', err);
  return c.json(
    { error: { code: 'internal_error', message: 'Internal server error' } },
    500,
  );
};

export const unauthorized = (msg = 'Unauthorized') => new ApiError(401, 'unauthorized', msg);
export const forbidden = (msg = 'Forbidden') => new ApiError(403, 'forbidden', msg);
export const notFound = (msg = 'Not found') => new ApiError(404, 'not_found', msg);
export const locked = (msg = 'Account locked') => new ApiError(423, 'account_locked', msg);
export const badRequest = (msg: string, details?: unknown) => new ApiError(400, 'bad_request', msg, details);

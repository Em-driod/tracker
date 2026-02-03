import { z } from 'zod';

export const loginSchema = z.object({
  identifier: z.string().min(1, 'Identifier is required'), // Could be email or username
  password: z.string().min(6, 'Password must be at least 6 characters long'),
});

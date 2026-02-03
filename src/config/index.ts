import dotenv from 'dotenv';
import { fido2, rpId, rpName, origin } from './webauthn';

dotenv.config();

export const config = {
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  email: {
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  webauthn: {
    fido2,
    rpId,
    rpName,
    origin,
  },
  paystack: {
    secretKey: process.env.PAYSTACK_SECRET_KEY,
  },
};

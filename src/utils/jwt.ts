import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import { config } from '../config';

export const generateToken = (payload: object, expiresIn: string = '1h'): string => {
  const options = { expiresIn: expiresIn };
  // @ts-ignore
  return jwt.sign(payload, config.jwtSecret as Secret, options);
};

export const verifyToken = (token: string): any => {
  try {
    return jwt.verify(token, config.jwtSecret as Secret);
  } catch (error) {
    return null;
  }
};

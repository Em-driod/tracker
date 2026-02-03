import bcrypt from 'bcrypt';
import { z } from 'zod';

const saltRounds = 10;

export const hashPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, saltRounds);
};

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};

export const checkPasswordStrength = (password: string): 'weak' | 'strong' | 'very strong' => {
  const hasLowerCase = /[a-z]/.test(password);
  const hasUpperCase = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbolOrSpace = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]/.test(password);

  const strength = [hasLowerCase, hasUpperCase, hasNumber, hasSymbolOrSpace].filter(Boolean).length;

  if (password.length < 8 || strength < 4) {
    return 'weak';
  }
  if (password.length >= 12 && strength >= 4) {
    return 'very strong';
  }
  return 'strong';
};

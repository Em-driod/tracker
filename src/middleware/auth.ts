import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';

export interface CustomRequest extends Request {
  user?: { userId: string };
}

export const authenticate = (req: CustomRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    // Log if the entire header is missing
    console.warn(`[API] Authorization header missing for request to ${req.originalUrl}`);
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const parts = authHeader.split(' ');

  // Check for 'Bearer <token>' format
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    console.warn(`[API] Token missing or invalid format for request to ${req.originalUrl}. Header: "${authHeader}"`);
    return res.status(401).json({ message: 'Token missing or invalid format' });
  }

  const token = parts[1];
  const decoded = verifyToken(token);

  if (!decoded) {
    console.warn(`[API] Invalid token for request to ${req.originalUrl}`);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }

  req.user = decoded;
  next();
};
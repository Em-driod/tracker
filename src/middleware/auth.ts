import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';

export interface CustomRequest extends Request {
  user?: { userId: string };
}

export const authenticate = (req: CustomRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    console.warn(`[API] Authorization header missing for request to ${req.originalUrl}`);
    return res.status(401).json({
      message: 'Authorization header missing',
      hint: 'Include "Authorization: Bearer <token>" header in your request'
    });
  }

  const parts = authHeader.split(' ');

  // Check for 'Bearer <token>' format
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    console.warn(`[API] Token missing or invalid format for request to ${req.originalUrl}. Header: "${authHeader}"`);
    return res.status(401).json({
      message: 'Token missing or invalid format',
      hint: 'Authorization header must be in format: "Bearer <token>"'
    });
  }

  const token = parts[1];
  const decoded = verifyToken(token);

  if (!decoded) {
    console.warn(`[API] Invalid or expired token for request to ${req.originalUrl}`);
    return res.status(401).json({
      message: 'Invalid or expired token',
      hint: 'Please log in again to get a new token'
    });
  }

  req.user = decoded;
  next();
};
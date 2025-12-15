
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// Define a custom Request interface that includes the user object
export interface AuthRequest extends Request {
  user?: {
    id: string;
    role: string;
    isAdmin: boolean;
    adminRole?: string;
  };
}

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_do_not_use_in_production';

export const protect = async (req: AuthRequest, res: any, next: NextFunction) => {
  let token;

  // Use type casting to access headers safely, handling potential type mismatches
  const authHeader = (req as any).headers?.authorization;

  if (
    authHeader &&
    typeof authHeader === 'string' &&
    authHeader.startsWith('Bearer')
  ) {
    try {
      // Get token from header
      token = authHeader.split(' ')[1];

      // Verify token
      const decoded = jwt.verify(token, JWT_SECRET) as any;

      // Attach user info to request (id, role, isAdmin, adminRole)
      // Note: We avoid fetching the full user from DB here for performance on every request,
      // relying on the data embedded in the token. If critical status (like isSuspended)
      // changes frequently, consider fetching from DB here.
      req.user = decoded;

      next();
    } catch (error) {
      console.error('Token verification failed:', error);
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

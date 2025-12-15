import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_do_not_use_in_production';

interface TokenPayload {
  id: string;
  role: string;
  isAdmin: boolean;
  adminRole?: string;
}

/**
 * Generates a JSON Web Token for authenticated users.
 * @param id - User ID
 * @param role - User Role (client/cleaner)
 * @param isAdmin - Boolean flag for admin status
 * @param adminRole - Specific admin role (Super, Support, etc.)
 * @returns Signed JWT string
 */
export const generateToken = (id: string, role: string, isAdmin: boolean, adminRole?: string): string => {
  const payload: TokenPayload = { id, role, isAdmin, adminRole };
  
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '30d', // Token expires in 30 days
  });
};

/**
 * Verifies a JWT token and returns the decoded payload.
 * @param token - The JWT string to verify
 * @returns Decoded payload or null if invalid
 */
export const verifyToken = (token: string): TokenPayload | null => {
  try {
    return jwt.verify(token, JWT_SECRET) as TokenPayload;
  } catch (error) {
    return null;
  }
};
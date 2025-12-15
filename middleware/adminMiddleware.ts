
import { Response, NextFunction } from 'express';
import { AuthRequest } from './authMiddleware';

// 1. General Admin Check (Any Admin)
export const admin = (req: AuthRequest, res: any, next: NextFunction) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ message: 'Access denied. Admin privileges required.' });
  }
};

// 2. Super Admin Check (Only 'Super')
export const superAdmin = (req: AuthRequest, res: any, next: NextFunction) => {
  if (req.user && req.user.isAdmin && req.user.adminRole === 'Super') {
    next();
  } else {
    res.status(403).json({ message: 'Access denied. Super Admin privileges required.' });
  }
};

// 3. Payment Admin Check ('Payment' or 'Super')
// Used for confirming escrow payments and marking jobs as paid
export const paymentAdmin = (req: AuthRequest, res: any, next: NextFunction) => {
  if (
    req.user && 
    req.user.isAdmin && 
    (req.user.adminRole === 'Payment' || req.user.adminRole === 'Super')
  ) {
    next();
  } else {
    res.status(403).json({ message: 'Access denied. Payment Admin privileges required.' });
  }
};

// 4. Verification Admin Check ('Verification' or 'Super')
// Used for approving subscription upgrades and verifying documents
export const verificationAdmin = (req: AuthRequest, res: any, next: NextFunction) => {
  if (
    req.user && 
    req.user.isAdmin && 
    (req.user.adminRole === 'Verification' || req.user.adminRole === 'Super')
  ) {
    next();
  } else {
    res.status(403).json({ message: 'Access denied. Verification Admin privileges required.' });
  }
};

// 5. Support Admin Check ('Support' or 'Super')
// Used for general user management (viewing users, resolving disputes)
export const supportAdmin = (req: AuthRequest, res: any, next: NextFunction) => {
  if (
    req.user && 
    req.user.isAdmin && 
    (req.user.adminRole === 'Support' || req.user.adminRole === 'Super')
  ) {
    next();
  } else {
    res.status(403).json({ message: 'Access denied. Support Admin privileges required.' });
  }
};

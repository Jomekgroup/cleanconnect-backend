import { Request } from 'express';

// ==========================================
// ENUMS & UNIONS
// ==========================================

export type UserRole = 'client' | 'cleaner' | 'admin';

export type AdminRole = 'Super' | 'Support' | 'Verification' | 'Payment';

export type PaymentMethod = 'Direct' | 'Escrow';

export type BookingStatus = 'Upcoming' | 'Completed' | 'Cancelled';

export type PaymentStatus = 
  | 'Pending Payment' 
  | 'Pending Admin Confirmation' 
  | 'Confirmed' 
  | 'Pending Payout' 
  | 'Paid' 
  | 'Not Applicable';

export type SubscriptionTier = 'Free' | 'Standard' | 'Pro' | 'Premium';

// ==========================================
// INTERFACES
// ==========================================

// The data structure stored inside the JWT
export interface JwtPayload {
  id: string;
  role: string; // Stored as string in DB, but logically UserRole
  isAdmin: boolean;
  adminRole?: string; // Stored as string in DB, but logically AdminRole
}

// Extension of Express.Request to include the authenticated user
export interface AuthRequest extends Request {
  user?: JwtPayload;
}

// Receipt structure for uploads
export interface ReceiptData {
  name: string;
  dataUrl: string; // Base64 string
}

// Structure for Contact Form submission
export interface ContactFormInput {
  topic: string;
  name: string;
  email: string;
  phone: string;
  message: string;
}

// Structure for AI Search Input
export interface AiSearchInput {
  query: string;
}

// File: middleware/authMiddleware.js

const jwt = require('jsonwebtoken');

/**
 * Enhanced authentication middleware with database integration
 * and comprehensive error handling
 */
const protect = async (req, res, next) => {
    let token;

    // Check for token in Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Extract token from "Bearer <token>"
            token = req.headers.authorization.split(' ')[1];

            // Verify token signature and expiration
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            console.log(`🔐 Token verified for user ID: ${decoded.id}`);

            // Get database pool from global context (set in server.js)
            const pool = global.db;
            
            if (!pool) {
                console.error('❌ Database pool not available');
                return res.status(503).json({ 
                    message: 'Service temporarily unavailable' 
                });
            }

            // Get user from database with active status check
            const userResult = await pool.query(
                `SELECT 
                    id, 
                    email, 
                    full_name, 
                    role, 
                    is_admin, 
                    is_active,
                    created_at
                 FROM users 
                 WHERE id = $1 AND is_active = true`,
                [decoded.id]
            );

            const user = userResult.rows[0];

            if (!user) {
                console.warn(`❌ User not found or inactive: ${decoded.id}`);
                return res.status(401).json({ 
                    message: 'Not authorized, user not found or account deactivated' 
                });
            }

            // Attach user to request object (excluding sensitive data)
            req.user = {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                isAdmin: user.is_admin,
                isActive: user.is_active,
                createdAt: user.created_at
            };

            console.log(`✅ User authenticated: ${user.email} (${user.role})`);
            
            // Proceed to next middleware/route
            return next();

        } catch (error) {
            console.error('❌ Token verification error:', error.message);

            // Handle specific JWT errors
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({ 
                    message: 'Not authorized, invalid token' 
                });
            }
            
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ 
                    message: 'Not authorized, token expired' 
                });
            }
            
            if (error.name === 'NotBeforeError') {
                return res.status(401).json({ 
                    message: 'Not authorized, token not active' 
                });
            }

            // Database or other errors
            console.error('Auth middleware error:', error);
            return res.status(500).json({ 
                message: 'Authentication service error' 
            });
        }
    }

    // No token provided
    console.warn('❌ No authorization token provided');
    return res.status(401).json({ 
        message: 'Not authorized, no token provided' 
    });
};

/**
 * Admin authorization middleware
 * Must be used after protect middleware
 */
const admin = (req, res, next) => {
    if (!req.user) {
        console.error('❌ Admin middleware called without user context');
        return res.status(500).json({ 
            message: 'Authorization system error' 
        });
    }

    if (req.user && req.user.isAdmin === true) {
        console.log(`👑 Admin access granted: ${req.user.email}`);
        return next();
    } else {
        console.warn(`🚫 Admin access denied: ${req.user.email}`);
        return res.status(403).json({ 
            message: 'Access denied. Admin privileges required.' 
        });
    }
};

/**
 * Role-based authorization middleware
 * @param {...string} allowedRoles - Roles that are permitted
 */
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            console.error('❌ Role middleware called without user context');
            return res.status(500).json({ 
                message: 'Authorization system error' 
            });
        }

        if (allowedRoles.includes(req.user.role) || req.user.isAdmin) {
            console.log(`✅ Role access granted: ${req.user.role} for ${req.user.email}`);
            return next();
        } else {
            console.warn(`🚫 Role access denied: ${req.user.role} for ${req.user.email}`);
            return res.status(403).json({ 
                message: `Access denied. Required roles: ${allowedRoles.join(', ')}` 
            });
        }
    };
};

/**
 * Optional authentication middleware
 * Attaches user if token is valid, but doesn't block request
 */
const optionalAuth = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            const pool = global.db;
            if (pool) {
                const userResult = await pool.query(
                    `SELECT id, email, full_name, role, is_admin, is_active
                     FROM users 
                     WHERE id = $1 AND is_active = true`,
                    [decoded.id]
                );

                const user = userResult.rows[0];
                if (user) {
                    req.user = {
                        id: user.id,
                        email: user.email,
                        fullName: user.full_name,
                        role: user.role,
                        isAdmin: user.is_admin,
                        isActive: user.is_active
                    };
                    console.log(`🔓 Optional auth - User attached: ${user.email}`);
                }
            }
        } catch (error) {
            // Silently fail for optional auth - don't attach user
            console.log('🔓 Optional auth - Invalid token, proceeding without user');
        }
    }
    
    next();
};

/**
 * Enhanced error handler for authentication failures
 */
const authErrorHandler = (err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({ 
            message: 'Invalid authentication token',
            code: 'INVALID_TOKEN'
        });
    }
    next(err);
};

module.exports = {
    protect,
    admin,
    requireRole,
    optionalAuth,
    authErrorHandler
};
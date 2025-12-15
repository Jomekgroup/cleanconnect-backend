
import { Request, Response, NextFunction } from 'express';

// Handle 404 - Not Found
export const notFound = (req: any, res: any, next: NextFunction) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  res.status(404);
  next(error);
};

// Global Error Handler
export const errorHandler = (err: any, req: Request, res: any, next: NextFunction) => {
  // If status code is 200 (OK) but there is an error, default to 500 (Server Error)
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;

  res.status(statusCode);

  res.json({
    message: err.message,
    // Only show stack trace in development mode for debugging
    stack: process.env.NODE_ENV === 'production' ? null : err.stack,
  });
};

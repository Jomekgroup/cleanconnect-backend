// File: middleware/upload.js
// Enhanced Multer + Cloudinary storage with better error handling and flexible file validation

const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('../utils/cloudinary');

/**
 * Allowed MIME types per field
 * - selfie, profilePhoto              -> images only
 * - governmentId, businessRegDoc, id  -> images or pdf
 */
const ALLOWED = {
  image: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'],
  imageOrPdf: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp', 'application/pdf'],
};

/**
 * Max file size per file (bytes)
 * 5 MB default - adjust if needed
 */
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

/**
 * CloudinaryStorage params factory
 * We set folder based on fieldname and allow resource_type 'auto' so PDFs are accepted.
 */
const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    // choose folder by incoming fieldname
    let folder = 'cleanconnect/others';
    if (['selfie'].includes(file.fieldname)) folder = 'cleanconnect/selfies';
    if (['profilePhoto'].includes(file.fieldname)) folder = 'cleanconnect/profiles';
    if (['governmentId', 'idDocument'].includes(file.fieldname)) folder = 'cleanconnect/ids';
    if (['businessRegDoc'].includes(file.fieldname)) folder = 'cleanconnect/business_docs';

    // resource_type 'auto' lets Cloudinary accept images, pdfs, etc.
    return {
      folder,
      resource_type: 'auto',
    };
  },
});

/**
 * Enhanced Multer file filter with better error messages
 */
const fileFilter = (req, file, cb) => {
  const field = file.fieldname;

  // decide allowed list based on field type
  let allowed = ALLOWED.imageOrPdf;
  if (['selfie', 'profilePhoto'].includes(field)) allowed = ALLOWED.image;
  if (['governmentId', 'idDocument', 'businessRegDoc'].includes(field)) allowed = ALLOWED.imageOrPdf;

  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    const error = new Error(`Invalid file type for "${field}". Allowed types: ${allowed.join(', ')}`);
    error.code = 'INVALID_FILE_TYPE';
    cb(error, false);
  }
};

/**
 * Main Multer instance
 */
const parser = multer({
  storage,
  fileFilter,
  limits: { 
    fileSize: MAX_FILE_SIZE,
    files: 10 // Maximum number of files
  },
});

/**
 * Enhanced error handling middleware for Multer
 */
const handleMulterErrors = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        message: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB.`
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        message: 'Too many files uploaded.'
      });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        message: `Unexpected file field: ${err.field}. Please check your file uploads.`
      });
    }
    return res.status(400).json({
      message: `Upload error: ${err.message}`
    });
  } else if (err && err.code === 'INVALID_FILE_TYPE') {
    return res.status(400).json({
      message: err.message
    });
  } else if (err) {
    console.error('Unknown upload error:', err);
    return res.status(500).json({
      message: 'Unknown error occurred during file upload.'
    });
  }
  next();
};

/**
 * Flexible upload middleware that handles optional files gracefully
 * This is the main middleware that should be used in routes
 */
const flexibleUpload = (req, res, next) => {
  // Use Multer to process files, but don't require all fields
  parser.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'idDocument', maxCount: 1 },
    { name: 'governmentId', maxCount: 1 },
    { name: 'profilePhoto', maxCount: 1 },
    { name: 'businessRegDoc', maxCount: 1 },
  ])(req, res, (err) => {
    if (err) {
      return handleMulterErrors(err, req, res, next);
    }
    
    // Clean up empty file arrays and validate file sizes
    if (req.files) {
      Object.keys(req.files).forEach(fieldName => {
        // Remove files that are empty or have no buffer
        req.files[fieldName] = req.files[fieldName].filter(file => 
          file && file.buffer && file.buffer.length > 0 && file.size > 0
        );
        
        // Remove empty arrays
        if (req.files[fieldName].length === 0) {
          delete req.files[fieldName];
        }
      });
      
      // Log uploaded files for debugging
      console.log('📁 Files uploaded:', Object.keys(req.files).map(key => ({
        field: key,
        files: req.files[key].map(f => ({
          name: f.originalname,
          size: f.size,
          type: f.mimetype
        }))
      })));
    }
    
    next();
  });
};

/**
 * Strict upload middleware for routes that require specific files
 * Use this when you want to enforce file requirements at the middleware level
 */
const strictUpload = (requiredFields) => {
  return (req, res, next) => {
    flexibleUpload(req, res, (err) => {
      if (err) return next(err);
      
      // Check if required files are present
      if (requiredFields && req.files) {
        const missingFields = requiredFields.filter(field => 
          !req.files[field] || req.files[field].length === 0
        );
        
        if (missingFields.length > 0) {
          return res.status(400).json({
            message: `Missing required files: ${missingFields.join(', ')}`
          });
        }
      }
      
      next();
    });
  };
};

/**
 * Backward compatibility - original uploadFields
 * @deprecated Use flexibleUpload or strictUpload instead
 */
const uploadFields = parser.fields([
  { name: 'selfie', maxCount: 1 },
  { name: 'idDocument', maxCount: 1 },
  { name: 'governmentId', maxCount: 1 },
  { name: 'profilePhoto', maxCount: 1 },
  { name: 'businessRegDoc', maxCount: 1 },
]);

module.exports = {
  parser,
  uploadFields, // Legacy export
  flexibleUpload, // Recommended for most use cases
  strictUpload, // Use when specific files are required
  handleMulterErrors,
  MAX_FILE_SIZE,
  ALLOWED
};
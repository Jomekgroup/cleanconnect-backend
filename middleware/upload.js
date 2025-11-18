// File: middleware/upload.js
// UPDATED VERSION - Compatible with SignupForm file structure

const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('../utils/cloudinary');

/**
 * Allowed MIME types per field - UPDATED FOR SIGNUPFORM
 * - profilePhoto -> images only
 * - governmentId, idDocument, businessRegDoc -> images or pdf
 */
const ALLOWED = {
  image: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'],
  imageOrPdf: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp', 'application/pdf'],
};

/**
 * Max file size per file (bytes)
 * 5 MB default - matches frontend
 */
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

/**
 * Use memory storage to get file buffers for validation
 * Then manually upload to Cloudinary in the controller
 */
const memoryStorage = multer.memoryStorage();

/**
 * Enhanced Multer file filter with better error messages - UPDATED FIELDS
 */
const fileFilter = (req, file, cb) => {
  const field = file.fieldname;

  // decide allowed list based on field type - UPDATED FOR SIGNUPFORM
  let allowed = ALLOWED.imageOrPdf;
  if (['profilePhoto'].includes(field)) allowed = ALLOWED.image;
  if (['governmentId', 'idDocument', 'businessRegDoc'].includes(field)) allowed = ALLOWED.imageOrPdf;

  if (allowed.includes(file.mimetype)) {
    console.log(`✅ File type accepted: ${file.fieldname} - ${file.mimetype}`);
    cb(null, true);
  } else {
    console.log(`❌ File type rejected: ${file.fieldname} - ${file.mimetype}`);
    const error = new Error(`Invalid file type for "${field}". Allowed types: ${allowed.join(', ')}`);
    error.code = 'INVALID_FILE_TYPE';
    cb(error, false);
  }
};

/**
 * UPDATED: Memory storage parser with SignupForm fields
 */
const memoryParser = multer({
  storage: memoryStorage,
  fileFilter,
  limits: { 
    fileSize: MAX_FILE_SIZE,
    files: 10
  },
});

/**
 * Enhanced error handling middleware for Multer
 */
const handleMulterErrors = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('❌ Multer error:', err.code, err.message);
    
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        message: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB.`
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        message: 'Too many files uploaded. Maximum is 10 files.'
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
    console.error('❌ Unknown upload error:', err);
    return res.status(500).json({
      message: 'Unknown error occurred during file upload.'
    });
  }
  next();
};

/**
 * UPDATED: Main upload middleware for SignupForm
 * Removed selfie field, added governmentId field
 */
const flexibleUpload = (req, res, next) => {
  console.log('🔄 Starting file upload processing for SignupForm...');
  
  memoryParser.fields([
    { name: 'idDocument', maxCount: 1 },
    { name: 'governmentId', maxCount: 1 },
    { name: 'profilePhoto', maxCount: 1 },
    { name: 'businessRegDoc', maxCount: 1 },
  ])(req, res, (err) => {
    if (err) {
      return handleMulterErrors(err, req, res, next);
    }
    
    // Log ALL file information for debugging
    console.log('🔍 SIGNUPFORM FILE UPLOAD DEBUG INFO:');
    console.log('Content-Type:', req.headers['content-type']);
    console.log('Request body keys:', Object.keys(req.body));
    
    if (req.files) {
      console.log('📁 Files processed by Multer:');
      Object.keys(req.files).forEach(fieldName => {
        const files = req.files[fieldName];
        console.log(`   ${fieldName}: ${files.length} file(s)`);
        files.forEach((file, index) => {
          console.log(`     File ${index + 1}:`);
          console.log(`       - originalname: ${file.originalname}`);
          console.log(`       - mimetype: ${file.mimetype}`);
          console.log(`       - size: ${file.size} bytes`);
          console.log(`       - buffer: ${file.buffer ? `${file.buffer.length} bytes` : 'NO BUFFER'}`);
          console.log(`       - fieldname: ${file.fieldname}`);
        });
      });
      
      // Handle governmentId/idDocument field mapping
      // Both fields should point to the same file for compatibility
      if (req.files.governmentId && !req.files.idDocument) {
        req.files.idDocument = req.files.governmentId;
        console.log('🔄 Mapped governmentId to idDocument for compatibility');
      } else if (req.files.idDocument && !req.files.governmentId) {
        req.files.governmentId = req.files.idDocument;
        console.log('🔄 Mapped idDocument to governmentId for compatibility');
      }
      
      // Remove empty files but KEEP files with buffers
      Object.keys(req.files).forEach(fieldName => {
        req.files[fieldName] = req.files[fieldName].filter(file => 
          file && file.size > 0
        );
        
        if (req.files[fieldName].length === 0) {
          delete req.files[fieldName];
        }
      });
      
      console.log('✅ Final files after filtering:', req.files ? Object.keys(req.files) : 'None');
    } else {
      console.log('❌ No files found in req.files');
    }
    
    next();
  });
};

/**
 * Strict upload middleware for routes that require specific files
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

// Backward compatibility
const uploadFields = flexibleUpload;

module.exports = {
  parser: memoryParser,
  uploadFields,
  flexibleUpload,
  handleMulterErrors,
  MAX_FILE_SIZE,
  ALLOWED
};
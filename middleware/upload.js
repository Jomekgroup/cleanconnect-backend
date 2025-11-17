// File: middleware/upload.js
// FIXED VERSION - Uses memory storage to provide file buffers

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
 * FIXED: Use memory storage to get file buffers for validation
 * Then manually upload to Cloudinary in the controller
 */
const memoryStorage = multer.memoryStorage();

/**
 * Cloudinary storage for actual file uploads (optional - can use memory storage only)
 */
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    let folder = 'cleanconnect/others';
    if (['selfie'].includes(file.fieldname)) folder = 'cleanconnect/selfies';
    if (['profilePhoto'].includes(file.fieldname)) folder = 'cleanconnect/profiles';
    if (['governmentId', 'idDocument'].includes(file.fieldname)) folder = 'cleanconnect/ids';
    if (['businessRegDoc'].includes(file.fieldname)) folder = 'cleanconnect/business_docs';

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
 * FIXED: Use memory storage to get file buffers
 */
const memoryParser = multer({
  storage: memoryStorage, // Use memory storage to get buffers
  fileFilter,
  limits: { 
    fileSize: MAX_FILE_SIZE,
    files: 10
  },
});

/**
 * Cloudinary parser (optional - if you want direct Cloudinary uploads)
 */
const cloudinaryParser = multer({
  storage: cloudinaryStorage,
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
 * FIXED: Main upload middleware that provides file buffers
 * This is the middleware you should use in your routes
 */
const flexibleUpload = (req, res, next) => {
  console.log('🔄 Starting file upload processing with memory storage...');
  
  memoryParser.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'idDocument', maxCount: 1 },
    { name: 'governmentId', maxCount: 1 },
    { name: 'profilePhoto', maxCount: 1 },
    { name: 'businessRegDoc', maxCount: 1 },
  ])(req, res, (err) => {
    if (err) {
      return handleMulterErrors(err, req, res, next);
    }
    
    // Log ALL file information for debugging
    console.log('🔍 FILE UPLOAD DEBUG INFO:');
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
      
      // Remove empty files but KEEP files with buffers (they will be uploaded to Cloudinary in controller)
      Object.keys(req.files).forEach(fieldName => {
        req.files[fieldName] = req.files[fieldName].filter(file => 
          file && file.size > 0 // Only check size, buffer will be available with memoryStorage
        );
        
        if (req.files[fieldName].length === 0) {
          delete req.files[fieldName];
        }
      });
      
      console.log('✅ Final files after filtering:', req.files ? Object.keys(req.files) : 'None');
    } else {
      console.log('❌ No files found in req.files - this indicates no files were uploaded');
    }
    
    next();
  });
};

/**
 * Alternative: Cloudinary direct upload middleware
 * Use this if you want files uploaded directly to Cloudinary
 */
const cloudinaryUpload = (req, res, next) => {
  console.log('🔄 Starting file upload processing with Cloudinary storage...');
  
  cloudinaryParser.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'idDocument', maxCount: 1 },
    { name: 'governmentId', maxCount: 1 },
    { name: 'profilePhoto', maxCount: 1 },
    { name: 'businessRegDoc', maxCount: 1 },
  ])(req, res, (err) => {
    if (err) {
      return handleMulterErrors(err, req, res, next);
    }
    
    console.log('✅ Cloudinary upload completed');
    if (req.files) {
      console.log('📁 Files uploaded to Cloudinary:', Object.keys(req.files));
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
  uploadFields, // Use flexibleUpload for backward compatibility
  flexibleUpload, // RECOMMENDED: Use this for memory storage with buffers
  cloudinaryUpload, // Alternative: Direct Cloudinary uploads (no buffers)
  strictUpload,
  handleMulterErrors,
  MAX_FILE_SIZE,
  ALLOWED
};
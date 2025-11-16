// File: middleware/upload.js
// Multer + Cloudinary storage with per-field rules, size/type validation and sensible defaults.

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
      // don't force a format for ids/document uploads since they can be PDF
    };
  },
});

/**
 * Multer file filter - enforce per-field mime types
 */
const fileFilter = (req, file, cb) => {
  const field = file.fieldname;

  // decide allowed list
  let allowed = ALLOWED.imageOrPdf;
  if (['selfie', 'profilePhoto'].includes(field)) allowed = ALLOWED.image;
  if (['governmentId', 'idDocument', 'businessRegDoc'].includes(field)) allowed = ALLOWED.imageOrPdf;

  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new multer.MulterError(
        'LIMIT_UNEXPECTED_FILE',
        `Invalid file type for "${field}". Allowed types: ${allowed.join(', ')}`
      )
    );
  }
};

/**
 * Multer instance
 * - Uses CloudinaryStorage to stream files to Cloudinary
 * - Applies fileFilter and size limit
 */
const parser = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE },
});

/**
 * Helper: fields configuration used by routes/auth.js (and anywhere else)
 * Keep this exported so routes can reuse the same config.
 *
 * Expected field names (frontend):
 * - selfie: single
 * - governmentId OR idDocument: single (some legacy code uses idDocument)
 * - profilePhoto: single (cleaner)
 * - businessRegDoc: single (cleaner - company)
 *
 * Example usage in route:
 * const { uploadFields } = require('../middleware/upload');
 * router.post('/register', uploadFields, controller.registerUser);
 *
 * We export both 'uploadFields' (multer middleware) and 'parser' for custom usages.
 */
const uploadFields = parser.fields([
  { name: 'selfie', maxCount: 1 },
  // accept both possible names used in various parts: 'governmentId' and 'idDocument'
  { name: 'governmentId', maxCount: 1 },
  { name: 'idDocument', maxCount: 1 },
  { name: 'profilePhoto', maxCount: 1 },
  { name: 'businessRegDoc', maxCount: 1 },
]);

/**
 * Export:
 * - parser (raw multer instance) if a route wants .single/.array/.fields directly
 * - uploadFields (pre-configured middleware) for convenience and consistency
 */
module.exports = {
  parser,
  uploadFields,
};

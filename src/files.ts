/**
 * FreeFormer R2 Storage & File Handling Module
 * Provides file sanitization, MIME-type and size security checks,
 * R2 persistence with namespaced keys, secure sandboxed file streaming,
 * and time-limited HMAC-signed URLs for webhook automation (Zapier, Make, etc.).
 */

import type { Context } from 'hono';
import type { Logger } from './logger';

export interface StoredAttachment {
  filename: string;
  key: string;
  size: number;
  mimeType: string;
  uploadedAt: string;
}

export const DISALLOWED_EXTENSIONS = new Set([
  'exe', 'dll', 'bat', 'cmd', 'sh', 'php', 'js', 'mjs', 'html', 'htm', 'svg', 'vbs', 'ps1', 'jar', 'com'
]);

export const DEFAULT_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

/**
 * Sanitizes a filename to a URL-safe, clean lowercase name
 */
export function sanitizeFilename(originalName: string): { base: string; ext: string; filename: string } {
  const cleanName = (originalName || 'unnamed-file').trim();
  const lastDotIndex = cleanName.lastIndexOf('.');
  const rawBase = lastDotIndex !== -1 ? cleanName.slice(0, lastDotIndex) : cleanName;
  const rawExt = lastDotIndex !== -1 ? cleanName.slice(lastDotIndex + 1) : '';

  const ext = rawExt.toLowerCase().replace(/[^a-z0-9]/g, '');
  const base = rawBase
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'file';

  const filename = ext ? `${base}.${ext}` : base;
  return { base, ext, filename };
}

/**
 * Validates a file before saving to R2
 */
export function validateAttachment(
  file: File,
  maxSizeBytes: number = DEFAULT_MAX_FILE_SIZE_BYTES
): { valid: boolean; error?: string } {
  if (file.size > maxSizeBytes) {
    const maxMb = (maxSizeBytes / (1024 * 1024)).toFixed(1);
    return {
      valid: false,
      error: `File "${file.name}" exceeds maximum allowed size of ${maxMb}MB`,
    };
  }

  const { ext } = sanitizeFilename(file.name);
  if (DISALLOWED_EXTENSIONS.has(ext)) {
    return {
      valid: false,
      error: `File extension ".${ext}" is not permitted for security reasons`,
    };
  }

  return { valid: true };
}

/**
 * Saves a file attachment to R2 with namespaced key
 */
export async function saveAttachmentToR2(
  bucket: R2Bucket,
  file: File,
  siteId: string,
  formId: string,
  submissionId: string,
  logger?: Logger
): Promise<StoredAttachment> {
  const { filename } = sanitizeFilename(file.name);
  // Key format: siteId/formId/submissionId/filename
  const key = `${siteId}/${formId}/${submissionId}/${filename}`;
  const mimeType = file.type || 'application/octet-stream';
  const size = file.size;
  const uploadedAt = new Date().toISOString();

  const arrayBuffer = await file.arrayBuffer();

  await bucket.put(key, arrayBuffer, {
    httpMetadata: {
      contentType: mimeType,
    },
    customMetadata: {
      originalName: file.name,
      siteId,
      formId,
      submissionId,
      uploadedAt,
    },
  });

  logger?.info('R2', `Saved attachment "${filename}" to key "${key}" (${size} bytes)`);

  return {
    filename,
    key,
    size,
    mimeType,
    uploadedAt,
  };
}

/**
 * Generate HMAC-SHA256 signature for signed download token
 */
async function generateHmacSignature(message: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create a time-limited HMAC-signed URL for webhook consumers (e.g. Zapier)
 */
export async function createSignedDownloadUrl(
  baseUrl: string,
  key: string,
  secret: string,
  ttlSeconds: number = 900 // 15 minutes
): Promise<string> {
  const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
  const message = `${key}:${expiresAt}`;
  const token = await generateHmacSignature(message, secret);

  const cleanBase = baseUrl.replace(/\/$/, '');
  const encodedKey = encodeURIComponent(key);
  return `${cleanBase}/files/signed?key=${encodedKey}&expires=${expiresAt}&token=${token}`;
}

/**
 * Verify a time-limited HMAC-signed URL
 */
export async function verifySignedDownloadToken(
  key: string,
  expiresStr: string,
  token: string,
  secret: string
): Promise<boolean> {
  const expiresAt = parseInt(expiresStr, 10);
  if (isNaN(expiresAt)) return false;

  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec > expiresAt) {
    return false; // Expired
  }

  const message = `${key}:${expiresAt}`;
  const expectedToken = await generateHmacSignature(message, secret);
  return expectedToken === token;
}

/**
 * Return sandboxed response headers for serving stored files
 */
export function getSandboxedFileHeaders(attachmentName: string, mimeType: string): Record<string, string> {
  return {
    'Content-Type': mimeType || 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${encodeURIComponent(attachmentName)}"`,
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Cache-Control': 'private, no-cache, no-store, must-revalidate',
  };
}

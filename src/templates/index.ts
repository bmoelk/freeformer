/**
 * FreeFormer Mustache Email Template Renderer
 * Imports .mustache files directly as the single source of truth.
 */

import Mustache from 'mustache';
import htmlTemplate from './email.html.mustache';
import textTemplate from './email.text.mustache';

export interface EmailTemplateData {
  formId: string;
  siteId?: string;
  submissionId: string;
  data: Record<string, any>;
  protectedFields?: string[];
  metadata: {
    ip: string;
    userAgent: string;
    timestamp: string;
    turnstileScore?: number;
  };
}

const SYSTEM_KEYS = new Set([
  'cf-turnstile-response',
  'cf_turnstile_response',
  'turnstileToken',
  'turnstile_token',
  'g-recaptcha-response',
  'formId',
  'form_id',
  'form',
  'siteId',
  'site_id',
  'site',
]);

/**
 * Checks if a key matches a pattern (supports exact match or * wildcards, case-insensitive)
 */
export function matchesPattern(key: string, pattern: string): boolean {
  const normKey = key.trim().toLowerCase();
  const normPattern = pattern.trim().toLowerCase();
  if (!normPattern) return false;
  if (normPattern === '*' || normPattern === normKey) return true;
  if (normPattern.includes('*')) {
    const escaped = normPattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`, 'i').test(normKey);
  }
  return normKey === normPattern;
}

/**
 * Determines whether a field is protected based on configured pattern list
 */
export function isFieldProtected(key: string, protectedPatterns?: string[]): boolean {
  if (!protectedPatterns || protectedPatterns.length === 0) return false;
  return protectedPatterns.some((pattern) => matchesPattern(key, pattern));
}

/**
 * Filter out system keys and protected fields from submission data and format as template fields array
 */
export function sanitizeSubmissionData(
  data: Record<string, any>,
  protectedFields?: string[]
): Array<{ key: string; value: string }> {
  const fields: Array<{ key: string; value: string }> = [];
  for (const [key, value] of Object.entries(data)) {
    if (!SYSTEM_KEYS.has(key) && !isFieldProtected(key, protectedFields)) {
      fields.push({
        key,
        value: typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value),
      });
    }
  }
  return fields;
}

/**
 * Render HTML Email via Mustache
 */
export function generateEmailHTML(submission: EmailTemplateData): string {
  const fields = sanitizeSubmissionData(submission.data, submission.protectedFields);
  const context = {
    formId: submission.formId,
    siteId: submission.siteId || null,
    submissionId: submission.submissionId,
    timestamp: new Date(submission.metadata.timestamp).toUTCString(),
    ip: submission.metadata.ip,
    turnstileScore: submission.metadata.turnstileScore !== undefined ? submission.metadata.turnstileScore.toFixed(2) : null,
    fields,
  };
  return Mustache.render(htmlTemplate, context);
}

/**
 * Render Plaintext Email via Mustache
 */
export function generateEmailTEXT(submission: EmailTemplateData): string {
  const fields = sanitizeSubmissionData(submission.data, submission.protectedFields);
  const context = {
    formId: submission.formId,
    siteId: submission.siteId || null,
    submissionId: submission.submissionId,
    timestamp: new Date(submission.metadata.timestamp).toUTCString(),
    ip: submission.metadata.ip,
    turnstileScore: submission.metadata.turnstileScore !== undefined ? submission.metadata.turnstileScore.toFixed(2) : null,
    fields,
  };
  return Mustache.render(textTemplate, context);
}

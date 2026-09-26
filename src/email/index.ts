/**
 * FreeFormer Email Subsystem
 * Polymorphic email notification module with multi-provider adapter support.
 */

import { type Logger } from '../logger';
import { generateEmailHTML, generateEmailTEXT } from '../templates';
import {
  type EmailAdapter,
  type EmailConfig,
  type EmailResult,
  type FormSubmissionData,
  type RawEmailPayload,
} from './types';
import { getEmailAdapter } from './registry';

export * from './types';
export * from './registry';
export * from './utils';
export * from './adapters/console';
export * from './adapters/resend';
export * from './adapters/sendgrid';
export * from './adapters/mailgun';
export * from './adapters/mailtrap';
export * from './adapters/zoho';

/**
 * Subject line generator for form submission notifications
 */
export function getEmailSubject(submission: FormSubmissionData): string {
  return submission.siteId
    ? `New Form Submission [${submission.siteId}]: ${submission.formId}`
    : `New Form Submission: ${submission.formId}`;
}

/**
 * Send arbitrary email (e.g. notifications, digests) via the configured provider
 */
export async function sendRawEmail(
  config: EmailConfig,
  payload: RawEmailPayload,
  logger?: Logger
): Promise<EmailResult> {
  logger?.debug(
    'Email',
    `Dispatching via provider: "${config.provider}" | From: "${config.from}" | To: "${config.to}" | SiteId: "${config.siteId || 'none'}"`
  );

  if (config.provider === 'none') {
    logger?.debug('Email', 'Skipped (provider is "none")');
    return { success: true };
  }

  const adapter = getEmailAdapter(config);
  if (!adapter) {
    logger?.error('Email', `Unknown email provider: "${config.provider}"`);
    return { success: false, error: `Unknown email provider: "${config.provider}"` };
  }

  // Console adapter does not require API key or destination
  if (config.provider !== 'console' && (!config.apiKey || !config.to)) {
    logger?.warn(
      'Email',
      `Skipped: apiKey configured? ${!!config.apiKey}, to="${config.to}"`
    );
    return { success: true };
  }

  try {
    return await adapter.send(payload, logger);
  } catch (error) {
    logger?.error('Email', 'Email dispatch exception', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Send email notification for form submission
 */
export async function sendEmailNotification(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<EmailResult> {
  const payload: RawEmailPayload = {
    subject: getEmailSubject(submission),
    html: generateEmailHTML(submission),
    text: generateEmailTEXT(submission),
  };
  return sendRawEmail(config, payload, logger);
}

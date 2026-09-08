/**
 * Email notification module
 * Supports multiple email providers: Resend, SendGrid, Mailgun, Mailtrap, Console
 */

import { type Logger } from './logger';
import { generateEmailHTML, generateEmailTEXT, sanitizeSubmissionData } from './templates';

export interface EmailConfig {
  provider: 'console' | 'resend' | 'sendgrid' | 'mailgun' | 'mailtrap' | 'none';
  apiKey: string;
  from: string;
  to: string;
  mailgunDomain?: string; // Required for Mailgun
  mailtrapInboxId?: string; // Required for Mailtrap (testing mode)
  siteId?: string;
  protectedFields?: string[];
}

export interface FormSubmissionData {
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

/**
 * Send email notification for form submission
 */
export async function sendEmailNotification(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  logger?.debug(
    'Email',
    `Dispatching via provider: "${config.provider}" | From: "${config.from}" | To: "${config.to}" | SiteId: "${config.siteId || 'none'}"`
  );

  if (config.provider === 'none') {
    logger?.debug('Email', 'Skipped (provider is "none")');
    return { success: true }; // Skip if not configured
  }

  if (config.provider === 'console') {
    return sendViaConsole(config, submission);
  }

  if (!config.apiKey || !config.to) {
    logger?.warn(
      'Email',
      `Skipped: apiKey configured? ${!!config.apiKey}, to="${config.to}"`
    );
    return { success: true };
  }

  try {
    switch (config.provider) {
      case 'resend':
        return await sendViaResend(config, submission, logger);
      case 'sendgrid':
        return await sendViaSendGrid(config, submission, logger);
      case 'mailgun':
        return await sendViaMailgun(config, submission, logger);
      case 'mailtrap':
        return await sendViaMailtrap(config, submission, logger);
      default:
        logger?.error('Email', `Unknown email provider: "${config.provider}"`);
        return { success: false, error: 'Unknown email provider' };
    }
  } catch (error) {
    logger?.error('Email', 'Email dispatch exception', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

function getEmailSubject(submission: FormSubmissionData): string {
  return submission.siteId
    ? `New Form Submission [${submission.siteId}]: ${submission.formId}`
    : `New Form Submission: ${submission.formId}`;
}

/**
 * Send email via Console (Dev Output)
 */
function sendViaConsole(
  config: EmailConfig,
  submission: FormSubmissionData
): { success: boolean } {
  const sanitizedData = sanitizeSubmissionData(submission.data, submission.protectedFields);

  console.log(`
┌────────────────────────────────────────────────────────────────────────┐
│ 📧 [FreeFormer Dev Email Logger]                                       │
├────────────────────────────────────────────────────────────────────────┤
│ Form ID:        ${submission.formId}
│ Site ID:        ${submission.siteId || 'none'}
│ Submission ID:  ${submission.submissionId}
│ To:             ${config.to || 'dev@example.com'}
│ From:           ${config.from || 'noreply@localhost'}
│ Subject:        ${getEmailSubject(submission)}
├────────────────────────────────────────────────────────────────────────┤
│ Form Data:
${JSON.stringify(sanitizedData, null, 2)}
└────────────────────────────────────────────────────────────────────────┘
`);
  return { success: true };
}

/**
 * Send email via Resend
 */
async function sendViaResend(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  logger?.debug('Resend', `Request | From: "${config.from}" | To: "${config.to}"`);

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: config.from,
      to: config.to.split(',').map(email => email.trim()),
      subject: getEmailSubject(submission),
      html: generateEmailHTML(submission),
      text: generateEmailTEXT(submission),
    }),
  });

  const responseText = await response.text();

  if (!response.ok) {
    logger?.error('Resend', `API Error (${response.status}): ${responseText}`);
    return { success: false, error: `Resend error (${response.status}): ${responseText}` };
  }

  logger?.debug('Resend', `API Success (${response.status}): ${responseText}`);
  return { success: true };
}

/**
 * Send email via SendGrid
 */
async function sendViaSendGrid(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  logger?.debug('SendGrid', `Request | From: "${config.from}" | To: "${config.to}"`);

  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [
        {
          to: config.to.split(',').map(email => ({ email: email.trim() })),
        },
      ],
      from: { email: config.from },
      subject: getEmailSubject(submission),
      content: [
        {
          type: 'text/plain',
          value: generateEmailTEXT(submission),
        },
        {
          type: 'text/html',
          value: generateEmailHTML(submission),
        },
      ],
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    logger?.error('SendGrid', `API Error (${response.status}): ${error}`);
    return { success: false, error: `SendGrid error: ${error}` };
  }

  logger?.debug('SendGrid', `API Success (${response.status})`);
  return { success: true };
}

/**
 * Send email via Mailgun
 */
async function sendViaMailgun(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  if (!config.mailgunDomain) {
    logger?.error('Mailgun', 'Missing mailgunDomain in configuration');
    return { success: false, error: 'Mailgun domain is required' };
  }

  logger?.debug('Mailgun', `Request | Domain: "${config.mailgunDomain}" | From: "${config.from}" | To: "${config.to}"`);

  const formData = new FormData();
  formData.append('from', config.from);
  formData.append('to', config.to);
  formData.append('subject', getEmailSubject(submission));
  formData.append('html', generateEmailHTML(submission));
  formData.append('text', generateEmailTEXT(submission));

  const response = await fetch(
    `https://api.mailgun.net/v3/${config.mailgunDomain}/messages`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${btoa(`api:${config.apiKey}`)}`,
      },
      body: formData,
    }
  );

  if (!response.ok) {
    const error = await response.text();
    logger?.error('Mailgun', `API Error (${response.status}): ${error}`);
    return { success: false, error: `Mailgun error: ${error}` };
  }

  logger?.debug('Mailgun', `API Success (${response.status})`);
  return { success: true };
}

/**
 * Send email via Mailtrap
 * Supports both testing (sandbox) and production modes
 */
async function sendViaMailtrap(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  const isSandbox = !!config.mailtrapInboxId;

  let url: string;
  let body: any;

  if (isSandbox) {
    url = `https://sandbox.api.mailtrap.io/api/send/${config.mailtrapInboxId}`;
    body = {
      from: { email: config.from },
      to: config.to.split(',').map(email => ({ email: email.trim() })),
      subject: getEmailSubject(submission),
      html: generateEmailHTML(submission),
      text: generateEmailTEXT(submission),
    };
  } else {
    url = 'https://send.api.mailtrap.io/api/send';
    body = {
      from: { email: config.from },
      to: config.to.split(',').map(email => ({ email: email.trim() })),
      subject: getEmailSubject(submission),
      html: generateEmailHTML(submission),
      text: generateEmailTEXT(submission),
    };
  }

  logger?.debug('Mailtrap', `Request URL: ${url} | From: "${config.from}" | To: "${config.to}"`);

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const responseText = await response.text();

  if (!response.ok) {
    logger?.error('Mailtrap', `API Error (${response.status}): ${responseText}`);
    return { success: false, error: `Mailtrap error: ${responseText}` };
  }

  logger?.debug('Mailtrap', `API Success (${response.status}): ${responseText}`);
  return { success: true };
}

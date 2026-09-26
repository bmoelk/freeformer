/**
 * Email notification module
 * Supports multiple email providers: Resend, SendGrid, Mailgun, Mailtrap, Console
 */

import { type Logger } from './logger';
import { generateEmailHTML, generateEmailTEXT, sanitizeSubmissionData } from './templates';

export interface EmailConfig {
  provider: 'console' | 'resend' | 'sendgrid' | 'mailgun' | 'mailtrap' | 'zoho' | 'zoho_cpaas' | 'zeptomail' | 'none';
  apiKey: string;
  from: string;
  to: string;
  mailgunDomain?: string; // Required for Mailgun
  mailtrapInboxId?: string; // Required for Mailtrap (testing mode)
  zohoApiUrl?: string; // Optional for Zoho CPaaS (defaults to https://cpaas.zoho.com/v1.1/email)
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

export interface RawEmailPayload {
  subject: string;
  html: string;
  text: string;
}

/**
 * Send arbitrary email (e.g. notifications, digests) via the configured provider
 */
export async function sendRawEmail(
  config: EmailConfig,
  payload: RawEmailPayload,
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
    return sendViaConsole(config, payload);
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
        return await sendViaResend(config, payload, logger);
      case 'sendgrid':
        return await sendViaSendGrid(config, payload, logger);
      case 'mailgun':
        return await sendViaMailgun(config, payload, logger);
      case 'mailtrap':
        return await sendViaMailtrap(config, payload, logger);
      case 'zoho':
      case 'zoho_cpaas':
      case 'zeptomail':
        return await sendViaZoho(config, payload, logger);
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

/**
 * Send email notification for form submission
 */
export async function sendEmailNotification(
  config: EmailConfig,
  submission: FormSubmissionData,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  const payload: RawEmailPayload = {
    subject: getEmailSubject(submission),
    html: generateEmailHTML(submission),
    text: generateEmailTEXT(submission),
  };
  return sendRawEmail(config, payload, logger);
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
  payload: RawEmailPayload
): { success: boolean } {
  console.log(`
┌────────────────────────────────────────────────────────────────────────┐
│ 📧 [FreeFormer Dev Email Logger]                                       │
├────────────────────────────────────────────────────────────────────────┤
│ To:             ${config.to || 'dev@example.com'}
│ From:           ${config.from || 'noreply@localhost'}
│ Subject:        ${payload.subject}
├────────────────────────────────────────────────────────────────────────┤
│ Content:
${payload.text}
└────────────────────────────────────────────────────────────────────────┘
`);
  return { success: true };
}

/**
 * Send email via Resend
 */
async function sendViaResend(
  config: EmailConfig,
  payload: RawEmailPayload,
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
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
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
  payload: RawEmailPayload,
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
      subject: payload.subject,
      content: [
        {
          type: 'text/plain',
          value: payload.text,
        },
        {
          type: 'text/html',
          value: payload.html,
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
  payload: RawEmailPayload,
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
  formData.append('subject', payload.subject);
  formData.append('html', payload.html);
  formData.append('text', payload.text);

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
  payload: RawEmailPayload,
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
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
    };
  } else {
    url = 'https://send.api.mailtrap.io/api/send';
    body = {
      from: { email: config.from },
      to: config.to.split(',').map(email => ({ email: email.trim() })),
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
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

/**
 * Parse an email string into address and optional display name
 * Supports formats: "user@example.com", "John Doe <user@example.com>"
 */
export function parseEmailAddress(input: string): { address: string; name?: string } {
  const trimmed = input.trim();
  const match = trimmed.match(/^(?:(.*?)<)?([^<>]+)>?$/);
  if (match && match[1]) {
    const name = match[1].trim().replace(/^["']|["']$/g, '');
    const address = match[2].trim();
    return name ? { address, name } : { address };
  }
  return { address: trimmed };
}

/**
 * Send email via Zoho CPaaS / ZeptoMail
 */
export async function sendViaZoho(
  config: EmailConfig,
  payload: RawEmailPayload,
  logger?: Logger
): Promise<{ success: boolean; error?: string }> {
  const endpoint = config.zohoApiUrl || 'https://cpaas.zoho.com/v1.1/email';
  logger?.debug('Zoho', `Request URL: ${endpoint} | From: "${config.from}" | To: "${config.to}"`);

  const trimmedKey = config.apiKey.trim();
  const authHeader = trimmedKey.startsWith('Zoho-enczapikey ')
    ? trimmedKey
    : `Zoho-enczapikey ${trimmedKey}`;

  const fromObj = parseEmailAddress(config.from);
  const toRecipients = config.to
    .split(',')
    .map(email => email.trim())
    .filter(Boolean)
    .map(email => ({
      email_address: parseEmailAddress(email),
    }));

  const body = {
    from: fromObj,
    to: toRecipients,
    subject: payload.subject,
    htmlbody: payload.html,
    textbody: payload.text,
  };

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization': authHeader,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const responseText = await response.text();

  if (!response.ok) {
    let parsedMessage = responseText;
    try {
      const errorJson = JSON.parse(responseText);
      if (errorJson.data?.message) {
        parsedMessage = `${errorJson.data.message}${errorJson.data.error_code ? ` (${errorJson.data.error_code})` : ''}`;
      } else if (errorJson.message) {
        parsedMessage = errorJson.message;
      }
    } catch {
      // Fall back to responseText
    }
    logger?.error('Zoho', `API Error (${response.status}): ${responseText}`);
    return { success: false, error: `Zoho error (${response.status}): ${parsedMessage}` };
  }

  logger?.debug('Zoho', `API Success (${response.status}): ${responseText}`);
  return { success: true };
}



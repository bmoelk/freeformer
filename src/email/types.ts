/**
 * FreeFormer Email Subsystem Types & Interfaces
 */

import { type Logger } from '../logger';

export interface EmailResult {
  success: boolean;
  error?: string;
}

export type EmailProviderType =
  | 'console'
  | 'resend'
  | 'sendgrid'
  | 'mailgun'
  | 'mailtrap'
  | 'zoho'
  | 'zoho_cpaas'
  | 'zeptomail'
  | 'none';

export interface EmailConfig {
  provider: EmailProviderType;
  apiKey: string;
  from: string;
  to: string;
  mailgunDomain?: string; // Required for Mailgun
  mailtrapInboxId?: string; // Required for Mailtrap (testing mode)
  zohoApiUrl?: string; // Optional for Zoho CPaaS (defaults to https://cpaas.zoho.com/v1.1/email)
  siteId?: string;
  protectedFields?: string[];
}

export interface RawEmailPayload {
  subject: string;
  html: string;
  text: string;
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
 * Polymorphic Email Adapter Interface
 * Every email provider encapsulates its own network calls, header formatting,
 * payload translation, and error handling behind this contract.
 */
export interface EmailAdapter {
  readonly name: string;
  send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult>;
}

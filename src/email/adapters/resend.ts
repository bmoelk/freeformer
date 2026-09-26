/**
 * Resend Email Adapter
 * Dispatches emails via Resend's REST API.
 */

import { type EmailAdapter, type EmailConfig, type EmailResult, type RawEmailPayload } from '../types';
import { type Logger } from '../../logger';

export class ResendEmailAdapter implements EmailAdapter {
  readonly name = 'resend';

  constructor(private config: EmailConfig) {}

  async send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult> {
    logger?.debug('Resend', `Request | From: "${this.config.from}" | To: "${this.config.to}"`);

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: this.config.from,
        to: this.config.to.split(',').map((email) => email.trim()),
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
}

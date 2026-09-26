/**
 * SendGrid Email Adapter
 * Dispatches emails via Twilio SendGrid v3 Mail Send API.
 */

import { type EmailAdapter, type EmailConfig, type EmailResult, type RawEmailPayload } from '../types';
import { type Logger } from '../../logger';

export class SendGridEmailAdapter implements EmailAdapter {
  readonly name = 'sendgrid';

  constructor(private config: EmailConfig) {}

  async send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult> {
    logger?.debug('SendGrid', `Request | From: "${this.config.from}" | To: "${this.config.to}"`);

    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [
          {
            to: this.config.to.split(',').map((email) => ({ email: email.trim() })),
          },
        ],
        from: { email: this.config.from },
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
}

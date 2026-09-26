/**
 * Mailtrap Email Adapter
 * Supports both sandbox (testing mode) and production sending endpoints.
 */

import { type EmailAdapter, type EmailConfig, type EmailResult, type RawEmailPayload } from '../types';
import { type Logger } from '../../logger';

export class MailtrapEmailAdapter implements EmailAdapter {
  readonly name = 'mailtrap';

  constructor(private config: EmailConfig) {}

  async send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult> {
    const isSandbox = !!this.config.mailtrapInboxId;

    let url: string;
    let body: any;

    if (isSandbox) {
      url = `https://sandbox.api.mailtrap.io/api/send/${this.config.mailtrapInboxId}`;
      body = {
        from: { email: this.config.from },
        to: this.config.to.split(',').map((email) => ({ email: email.trim() })),
        subject: payload.subject,
        html: payload.html,
        text: payload.text,
      };
    } else {
      url = 'https://send.api.mailtrap.io/api/send';
      body = {
        from: { email: this.config.from },
        to: this.config.to.split(',').map((email) => ({ email: email.trim() })),
        subject: payload.subject,
        html: payload.html,
        text: payload.text,
      };
    }

    logger?.debug('Mailtrap', `Request URL: ${url} | From: "${this.config.from}" | To: "${this.config.to}"`);

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
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
}

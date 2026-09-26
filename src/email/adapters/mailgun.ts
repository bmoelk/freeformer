/**
 * Mailgun Email Adapter
 * Dispatches emails via Mailgun v3 Messages API.
 */

import { type EmailAdapter, type EmailConfig, type EmailResult, type RawEmailPayload } from '../types';
import { type Logger } from '../../logger';

export class MailgunEmailAdapter implements EmailAdapter {
  readonly name = 'mailgun';

  constructor(private config: EmailConfig) {}

  async send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult> {
    if (!this.config.mailgunDomain) {
      logger?.error('Mailgun', 'Missing mailgunDomain in configuration');
      return { success: false, error: 'Mailgun domain is required' };
    }

    logger?.debug(
      'Mailgun',
      `Request | Domain: "${this.config.mailgunDomain}" | From: "${this.config.from}" | To: "${this.config.to}"`
    );

    const formData = new FormData();
    formData.append('from', this.config.from);
    formData.append('to', this.config.to);
    formData.append('subject', payload.subject);
    formData.append('html', payload.html);
    formData.append('text', payload.text);

    const response = await fetch(
      `https://api.mailgun.net/v3/${this.config.mailgunDomain}/messages`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${btoa(`api:${this.config.apiKey}`)}`,
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
}

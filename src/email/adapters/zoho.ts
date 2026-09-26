/**
 * Zoho CPaaS & ZeptoMail Email Adapter
 * Dispatches transactional emails via Zoho's edge-native REST API.
 */

import { type EmailAdapter, type EmailConfig, type EmailResult, type RawEmailPayload } from '../types';
import { parseEmailAddress, parseEmailList } from '../utils';
import { type Logger } from '../../logger';

export class ZohoEmailAdapter implements EmailAdapter {
  readonly name = 'zoho';

  constructor(private config: EmailConfig) {}

  async send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult> {
    const endpoint = this.config.zohoApiUrl || 'https://cpaas.zoho.com/v1.1/email';
    logger?.debug('Zoho', `Request URL: ${endpoint} | From: "${this.config.from}" | To: "${this.config.to}"`);

    const trimmedKey = this.config.apiKey.trim();
    const authHeader = trimmedKey.startsWith('Zoho-enczapikey ')
      ? trimmedKey
      : `Zoho-enczapikey ${trimmedKey}`;

    const fromObj = parseEmailAddress(this.config.from);
    const toRecipients = parseEmailList(this.config.to).map((parsed) => ({
      email_address: parsed,
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
}

/**
 * Functional helper for dispatching via ZohoEmailAdapter
 */
export async function sendViaZoho(
  config: EmailConfig,
  payload: RawEmailPayload,
  logger?: Logger
): Promise<EmailResult> {
  return new ZohoEmailAdapter(config).send(payload, logger);
}


/**
 * Email Adapter Registry & Factory
 * Central registry mapping provider keys and aliases to polymorphic adapters.
 */

import { type EmailAdapter, type EmailConfig } from './types';
import { ConsoleEmailAdapter } from './adapters/console';
import { ResendEmailAdapter } from './adapters/resend';
import { SendGridEmailAdapter } from './adapters/sendgrid';
import { MailgunEmailAdapter } from './adapters/mailgun';
import { MailtrapEmailAdapter } from './adapters/mailtrap';
import { ZohoEmailAdapter } from './adapters/zoho';

export type EmailAdapterFactory = (config: EmailConfig) => EmailAdapter;

const adapterRegistry = new Map<string, EmailAdapterFactory>();

/**
 * Register an email provider factory
 */
export function registerEmailAdapter(name: string, factory: EmailAdapterFactory): void {
  adapterRegistry.set(name.toLowerCase(), factory);
}

/**
 * Get an adapter instance for the specified configuration
 */
export function getEmailAdapter(config: EmailConfig): EmailAdapter | null {
  const provider = (config.provider || 'none').toLowerCase();
  const factory = adapterRegistry.get(provider);
  return factory ? factory(config) : null;
}

// Register default built-in adapters
registerEmailAdapter('console', (cfg) => new ConsoleEmailAdapter(cfg));
registerEmailAdapter('resend', (cfg) => new ResendEmailAdapter(cfg));
registerEmailAdapter('sendgrid', (cfg) => new SendGridEmailAdapter(cfg));
registerEmailAdapter('mailgun', (cfg) => new MailgunEmailAdapter(cfg));
registerEmailAdapter('mailtrap', (cfg) => new MailtrapEmailAdapter(cfg));
registerEmailAdapter('zoho', (cfg) => new ZohoEmailAdapter(cfg));
registerEmailAdapter('zoho_cpaas', (cfg) => new ZohoEmailAdapter(cfg));
registerEmailAdapter('zeptomail', (cfg) => new ZohoEmailAdapter(cfg));

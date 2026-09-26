/**
 * Console Dev Email Adapter
 * Outputs formatted email ASCII box directly to Worker console logs.
 */

import { type EmailAdapter, type EmailConfig, type EmailResult, type RawEmailPayload } from '../types';
import { type Logger } from '../../logger';

export class ConsoleEmailAdapter implements EmailAdapter {
  readonly name = 'console';

  constructor(private config: EmailConfig) {}

  async send(payload: RawEmailPayload, logger?: Logger): Promise<EmailResult> {
    console.log(`
┌────────────────────────────────────────────────────────────────────────┐
│ 📧 [FreeFormer Dev Email Logger]                                       │
├────────────────────────────────────────────────────────────────────────┤
│ To:             ${this.config.to || 'dev@example.com'}
│ From:           ${this.config.from || 'noreply@localhost'}
│ Subject:        ${payload.subject}
├────────────────────────────────────────────────────────────────────────┤
│ Content:
${payload.text}
└────────────────────────────────────────────────────────────────────────┘
`);
    return { success: true };
  }
}

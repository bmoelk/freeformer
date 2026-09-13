/**
 * FreeFormer Spam Digest Dispatcher
 * Aggregates quarantined spam submissions over a configured timeframe
 * and dispatches a summary digest only if spam was detected (Zero-Noise).
 */

import { type Logger } from '../logger';
import { type EmailConfig, sendRawEmail } from '../email';
import { generateDigestHTML, generateDigestTEXT } from '../templates';
import { type StoredSubmission, getSubmissions } from '../storage';
import { type SpamDigestData, type SpamDigestItem } from './types';

export interface DigestOptions {
  days?: number;
  siteId?: string;
  adminUrl?: string;
  dryRun?: boolean;
}

export interface DigestResult {
  sent: boolean;
  reason?: string;
  count: number;
  digestData?: SpamDigestData;
  error?: string;
}

/**
 * Generates and sends a spam digest for a given timeframe
 */
export async function generateAndSendSpamDigest(
  storage: { kv?: KVNamespace; db?: D1Database },
  emailConfig: EmailConfig,
  options: DigestOptions = {},
  logger?: Logger
): Promise<DigestResult> {
  const days = options.days || 7;
  const cutoffTime = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const now = new Date();

  let submissions: StoredSubmission[] = [];

  if (storage.db) {
    let query = `SELECT id, form_id, site_id, data, metadata, created_at FROM submissions WHERE created_at >= ?`;
    const params: any[] = [cutoffTime];

    if (options.siteId) {
      query += ` AND site_id = ?`;
      params.push(options.siteId.toLowerCase());
    }
    query += ` ORDER BY created_at DESC LIMIT 1000`;

    const result = await storage.db.prepare(query).bind(...params).all();
    submissions = (result.results || []).map((row: any) => ({
      id: row.id,
      formId: row.form_id,
      siteId: row.site_id,
      data: JSON.parse(row.data || '{}'),
      metadata: JSON.parse(row.metadata || '{}'),
    }));
  } else if (storage.kv) {
    // KV storage: fetch up to 500 recent submissions
    submissions = await getSubmissions(storage.kv, undefined, undefined, options.siteId, 500, 0);
    // Filter by cutoff time
    submissions = submissions.filter((s) => (s.metadata?.timestamp || '') >= cutoffTime);
  }

  // Partition into spam vs clean
  const spamList: StoredSubmission[] = [];
  const cleanList: StoredSubmission[] = [];

  for (const sub of submissions) {
    const isSpam = sub.metadata?.spam?.isSpam ?? sub.metadata?.isSpam ?? false;
    if (isSpam) {
      spamList.push(sub);
    } else {
      cleanList.push(sub);
    }
  }

  // Zero-Noise Guarantee: If no spam was detected, send nothing!
  if (spamList.length === 0) {
    logger?.info('Digest', `No spam submissions detected in the last ${days} days. Digest suppressed.`);
    return {
      sent: false,
      reason: 'no_spam',
      count: 0,
    };
  }

  const total = spamList.length + cleanList.length;
  const spamPercentage = total > 0 ? `${((spamList.length / total) * 100).toFixed(1)}%` : '0%';

  const items: SpamDigestItem[] = spamList.slice(0, 50).map((sub) => {
    const senderName = sub.data?.name || sub.data?.fullName || sub.data?.contact_name || undefined;
    const senderEmail = sub.data?.email || sub.data?.email_address || undefined;
    const score = sub.metadata?.spam?.score ?? sub.metadata?.spamScore ?? 0;
    const topReason = sub.metadata?.spam?.reasons?.[0] || 'Flagged by spam engine';

    let snippet = '';
    if (typeof sub.data?.message === 'string') {
      snippet = sub.data.message;
    } else if (typeof sub.data?.comment === 'string') {
      snippet = sub.data.comment;
    } else {
      const keys = Object.keys(sub.data || {}).filter((k) => k !== 'email' && k !== 'name');
      snippet = keys.map((k) => `${k}: ${sub.data[k]}`).join(' | ');
    }

    if (snippet.length > 120) {
      snippet = snippet.slice(0, 117) + '...';
    }

    const dateStr = sub.metadata?.timestamp
      ? new Date(sub.metadata.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      : 'Unknown';

    return {
      id: sub.id,
      siteId: sub.siteId,
      formId: sub.formId,
      timestamp: dateStr,
      senderName,
      senderEmail,
      score,
      topReason,
      snippet,
    };
  });

  const periodStartDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const periodEndDate = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

  const digestData: SpamDigestData = {
    periodStart: periodStartDate,
    periodEnd: periodEndDate,
    totalSubmissions: total,
    spamSubmissions: spamList.length,
    cleanSubmissions: cleanList.length,
    spamPercentage,
    items,
    adminUrl: options.adminUrl,
  };

  if (options.dryRun) {
    return {
      sent: true,
      count: spamList.length,
      digestData,
    };
  }

  // Check email configuration
  if (emailConfig.provider === 'none' || !emailConfig.to) {
    logger?.warn('Digest', 'Spam detected but email provider is "none" or EMAIL_TO is not configured');
    return {
      sent: false,
      reason: 'email_not_configured',
      count: spamList.length,
      digestData,
    };
  }

  const subject = `🛡️ FreeFormer Weekly Spam Digest (${spamList.length} quarantined)`;
  const html = generateDigestHTML(digestData);
  const text = generateDigestTEXT(digestData);

  const result = await sendRawEmail(
    emailConfig,
    { subject, html, text },
    logger
  );

  if (!result.success) {
    logger?.error('Digest', `Failed to send spam digest email: ${result.error}`);
    return {
      sent: false,
      count: spamList.length,
      error: result.error,
      digestData,
    };
  }

  logger?.info('Digest', `Successfully sent spam digest with ${spamList.length} quarantined items to ${emailConfig.to}`);
  return {
    sent: true,
    count: spamList.length,
    digestData,
  };
}

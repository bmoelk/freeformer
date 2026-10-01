import { type Logger } from '../logger';
import { type EmailConfig, sendRawEmail } from '../email';
import { generateDigestHTML, generateDigestTEXT } from '../templates';
import { type StoredSubmission, getSubmissions } from '../storage';
import {
  type SpamDigestData,
  type SpamDigestItem,
  type DigestLegitItem,
  type DigestQuestionableSpamItem,
} from './types';

export interface DigestOptions {
  days?: number;
  siteId?: string;
  adminUrl?: string;
  dryRun?: boolean;
  mode?: 'comprehensive' | 'spam_only';
}

export interface DigestResult {
  sent: boolean;
  reason?: string;
  count: number;
  digestData?: SpamDigestData;
  error?: string;
}

function formatSnippet(data: Record<string, any>): string {
  if (typeof data?.message === 'string') return data.message;
  if (typeof data?.comment === 'string') return data.comment;
  const keys = Object.keys(data || {}).filter((k) => k !== 'email' && k !== 'name');
  return keys.map((k) => `${k}: ${data[k]}`).join(' | ');
}

function truncate(text: string, len: number = 120): string {
  return text.length > len ? text.slice(0, len - 3) + '...' : text;
}

/**
 * Generates and sends a weekly digest for a given timeframe
 */
export async function generateAndSendSpamDigest(
  storage: { kv?: KVNamespace; db?: D1Database },
  emailConfig: EmailConfig,
  options: DigestOptions = {},
  logger?: Logger
): Promise<DigestResult> {
  const days = options.days || 7;
  const mode = options.mode || 'spam_only';
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

  // Sort clean submissions chronologically (oldest first)
  cleanList.sort((a, b) =>
    (a.metadata?.timestamp || '').localeCompare(b.metadata?.timestamp || '')
  );

  // Sort spam submissions by score ascending (lowest score / closest to threshold first)
  spamList.sort(
    (a, b) =>
      (a.metadata?.spam?.score ?? a.metadata?.spamScore ?? 0) -
      (b.metadata?.spam?.score ?? b.metadata?.spamScore ?? 0)
  );

  // Suppression logic based on mode
  if (mode === 'spam_only') {
    if (spamList.length === 0) {
      logger?.info('Digest', `[spam_only] No spam submissions detected in the last ${days} days. Digest suppressed.`);
      return {
        sent: false,
        reason: 'no_spam',
        count: 0,
      };
    }
  } else {
    // Comprehensive mode: suppress only if 0 total submissions
    if (submissions.length === 0) {
      logger?.info('Digest', `[comprehensive] No submissions received in the last ${days} days. Digest suppressed.`);
      return {
        sent: false,
        reason: 'no_submissions',
        count: 0,
      };
    }
  }

  const total = spamList.length + cleanList.length;
  const spamPercentage = total > 0 ? `${((spamList.length / total) * 100).toFixed(1)}%` : '0%';

  // 1. Process Clean / Legitimate Inquiries
  const formatLegitItem = (sub: StoredSubmission): DigestLegitItem => {
    const senderName = sub.data?.name || sub.data?.fullName || sub.data?.contact_name || undefined;
    const senderEmail = sub.data?.email || sub.data?.email_address || undefined;
    const dateStr = sub.metadata?.timestamp
      ? new Date(sub.metadata.timestamp).toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        })
      : 'Unknown';

    return {
      id: sub.id,
      siteId: sub.siteId,
      formId: sub.formId,
      timestamp: dateStr,
      senderName,
      senderEmail,
      snippet: truncate(formatSnippet(sub.data)),
    };
  };

  const isDeduplicatedList = cleanList.length <= 10;
  let allLegitItems: DigestLegitItem[] | undefined;
  let earliestLegitItems: DigestLegitItem[] | undefined;
  let latestLegitItems: DigestLegitItem[] | undefined;

  if (cleanList.length > 0) {
    if (isDeduplicatedList) {
      allLegitItems = cleanList.map(formatLegitItem);
    } else {
      earliestLegitItems = cleanList.slice(0, 5).map(formatLegitItem);
      latestLegitItems = cleanList.slice(-5).map(formatLegitItem);
    }
  }

  // 2. Process Questionable / Borderline Spam (Human Review & Model Training Signals)
  const borderlineThreshold = 80;
  let questionable = spamList.filter((s) => {
    const score = s.metadata?.spam?.score ?? s.metadata?.spamScore ?? 0;
    return score < borderlineThreshold;
  });

  if (questionable.length === 0 && spamList.length > 0) {
    questionable = spamList.slice(0, 5);
  } else if (questionable.length > 10) {
    questionable = questionable.slice(0, 10);
  }

  const highConfidenceSpamCount = Math.max(0, spamList.length - questionable.length);

  const questionableSpamItems: DigestQuestionableSpamItem[] = questionable.map((sub) => {
    const senderName = sub.data?.name || sub.data?.fullName || sub.data?.contact_name || undefined;
    const senderEmail = sub.data?.email || sub.data?.email_address || undefined;
    const score = sub.metadata?.spam?.score ?? sub.metadata?.spamScore ?? 0;
    const topReason = sub.metadata?.spam?.reasons?.[0] || 'Flagged by spam engine';
    const dateStr = sub.metadata?.timestamp
      ? new Date(sub.metadata.timestamp).toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        })
      : 'Unknown';

    return {
      id: sub.id,
      siteId: sub.siteId,
      formId: sub.formId,
      timestamp: dateStr,
      senderName,
      senderEmail,
      score,
      borderlineScore: score,
      confidenceTier: score <= 75 ? 'borderline' : 'moderate',
      topReason,
      snippet: truncate(formatSnippet(sub.data)),
    };
  });

  const periodStartDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
  });
  const periodEndDate = now.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  const digestData: SpamDigestData = {
    periodStart: periodStartDate,
    periodEnd: periodEndDate,
    totalSubmissions: total,
    spamSubmissions: spamList.length,
    cleanSubmissions: cleanList.length,
    spamPercentage,
    hasLegitItems: cleanList.length > 0,
    isDeduplicatedList,
    earliestLegitItems,
    latestLegitItems,
    allLegitItems,
    hasQuestionableSpam: questionableSpamItems.length > 0,
    questionableSpamItems,
    highConfidenceSpamCount,
    items: questionableSpamItems, // backwards compatibility
    adminUrl: options.adminUrl,
  };

  if (options.dryRun) {
    return {
      sent: true,
      count: total,
      digestData,
    };
  }

  // Check email configuration
  if (emailConfig.provider === 'none' || !emailConfig.to) {
    logger?.warn('Digest', 'Digest generated but email provider is "none" or EMAIL_TO is not configured');
    return {
      sent: false,
      reason: 'email_not_configured',
      count: total,
      digestData,
    };
  }

  const subject =
    mode === 'spam_only'
      ? `🛡️ FreeFormer Weekly Spam Digest (${spamList.length} quarantined)`
      : `🛡️ FreeFormer Weekly Digest (${cleanList.length} inquiries, ${spamList.length} quarantined)`;

  const html = generateDigestHTML(digestData);
  const text = generateDigestTEXT(digestData);

  const result = await sendRawEmail(
    emailConfig,
    { subject, html, text },
    logger
  );

  if (!result.success) {
    logger?.error('Digest', `Failed to send digest email: ${result.error}`);
    return {
      sent: false,
      count: total,
      error: result.error,
      digestData,
    };
  }

  logger?.info(
    'Digest',
    `Successfully sent digest with ${cleanList.length} clean and ${spamList.length} quarantined items to ${emailConfig.to}`
  );
  return {
    sent: true,
    count: total,
    digestData,
  };
}

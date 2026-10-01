import type { SpamCategory } from './keywords';

export interface SpamMetrics {
  linkCount: number;
  linkDensity: number; // Ratio of URL characters to total text length (0.0 - 1.0)
  hasHoneypot: boolean;
  honeypotFieldName?: string;
  disposableEmail: boolean;
  suspiciousTld: boolean;
  timeToSubmitSeconds?: number;
  turnstileScore?: number;
  turnstileElapsedSeconds?: number;
  keywordMatches: string[];
  categoryMatches?: string[];
}

export interface SpamAnalysisResult {
  engineVersion: string;
  score: number; // 0 to 100
  isSpam: boolean; // score >= threshold
  threshold: number;
  reasons: string[];
  metrics: SpamMetrics;
  analyzedAt: string; // ISO-8601
  appliedCategories?: SpamCategory[];
}

export interface SpamEvaluationOptions {
  threshold?: number;
  categories?: SpamCategory[] | string[] | string;
  honeypotFields?: string[];
  customKeywords?: string[];
  clientIp?: string;
  turnstileResult?: {
    success: boolean;
    score?: number;
    challenge_ts?: string;
  };
  requestTimestamp?: number; // millisecond timestamp when request arrived at worker
}

export interface SpamDigestItem {
  id: string;
  siteId: string;
  formId: string;
  timestamp: string;
  senderName?: string;
  senderEmail?: string;
  score: number;
  topReason: string;
  snippet: string;
}

export interface DigestLegitItem {
  id: string;
  siteId: string;
  formId: string;
  timestamp: string;
  senderName?: string;
  senderEmail?: string;
  snippet: string;
}

export interface DigestQuestionableSpamItem extends SpamDigestItem {
  borderlineScore: number;
  confidenceTier: 'borderline' | 'moderate';
}

export interface SpamDigestData {
  periodStart: string;
  periodEnd: string;
  totalSubmissions: number;
  spamSubmissions: number;
  cleanSubmissions: number;
  spamPercentage: string;

  // Legitimate Inquiries
  hasLegitItems?: boolean;
  isDeduplicatedList?: boolean;
  earliestLegitItems?: DigestLegitItem[]; // "Ensure Follow-up" (first 5)
  latestLegitItems?: DigestLegitItem[];   // "Recent Reminder" (last 5)
  allLegitItems?: DigestLegitItem[];     // Single unified list when total <= 10

  // Questionable / Borderline Spam
  hasQuestionableSpam?: boolean;
  questionableSpamItems?: DigestQuestionableSpamItem[];
  highConfidenceSpamCount?: number;

  // Backwards compatibility for existing templates/tests
  items: SpamDigestItem[];
  adminUrl?: string;
}


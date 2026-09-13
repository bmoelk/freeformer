/**
 * FreeFormer Spam Detection & Telemetry Types
 */

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
}

export interface SpamAnalysisResult {
  engineVersion: string;
  score: number; // 0 to 100
  isSpam: boolean; // score >= threshold
  threshold: number;
  reasons: string[];
  metrics: SpamMetrics;
  analyzedAt: string; // ISO-8601
}

export interface SpamEvaluationOptions {
  threshold?: number;
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

export interface SpamDigestData {
  periodStart: string;
  periodEnd: string;
  totalSubmissions: number;
  spamSubmissions: number;
  cleanSubmissions: number;
  spamPercentage: string;
  items: SpamDigestItem[];
  adminUrl?: string;
}

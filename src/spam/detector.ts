/**
 * FreeFormer Edge Spam Detection Engine
 * Evaluates submissions across honeypots, timing velocity, links, disposable emails,
 * and weighted keyword dictionaries.
 */

import {
  type SpamAnalysisResult,
  type SpamEvaluationOptions,
  type SpamMetrics,
} from './types';
import { SPAM_PATTERNS } from './keywords';
import { isDisposableEmail, hasSuspiciousTld } from './disposable-domains';

export const SPAM_ENGINE_VERSION = '1.0.0';

export const DEFAULT_HONEYPOT_FIELDS = [
  '_hp',
  '_gotcha',
  'gotcha',
  'honeypot',
  '_honeypot',
  'website',
  'fax',
  'fax_number',
  'company_url',
  'url_check',
];

const URL_REGEX = /(?:https?:\/\/|www\.)[^\s/$.?#].[^\s]*/gi;

/**
 * Evaluates a form submission payload and produces an audit breakdown and spam score (0 - 100).
 */
export function evaluateSpam(
  data: Record<string, any>,
  options: SpamEvaluationOptions = {}
): SpamAnalysisResult {
  const threshold = typeof options.threshold === 'number' ? options.threshold : 60;
  const honeypotKeys = options.honeypotFields && options.honeypotFields.length > 0
    ? options.honeypotFields
    : DEFAULT_HONEYPOT_FIELDS;

  let rawScore = 0;
  const reasons: string[] = [];

  const metrics: SpamMetrics = {
    linkCount: 0,
    linkDensity: 0,
    hasHoneypot: false,
    disposableEmail: false,
    suspiciousTld: false,
    keywordMatches: [],
  };

  // 1. Check Honeypot Fields
  for (const [key, value] of Object.entries(data)) {
    const normKey = key.trim().toLowerCase();
    const isHoneypotField = honeypotKeys.some(
      (hp) => hp.toLowerCase() === normKey
    );

    if (isHoneypotField && value !== undefined && value !== null) {
      const strVal = String(value).trim();
      if (strVal.length > 0) {
        metrics.hasHoneypot = true;
        metrics.honeypotFieldName = key;
        rawScore += 80;
        reasons.push(`HONEYPOT_FILLED: Field "${key}" was populated (+80)`);
        break; // Stop after first honeypot trigger
      }
    }
  }

  // 2. Turnstile Timing / Submission Velocity
  if (options.turnstileResult?.challenge_ts) {
    try {
      const challengeTime = new Date(options.turnstileResult.challenge_ts).getTime();
      const reqTime = options.requestTimestamp || Date.now();
      const elapsedSeconds = Math.max(0, (reqTime - challengeTime) / 1000);
      metrics.turnstileElapsedSeconds = Number(elapsedSeconds.toFixed(2));
      metrics.timeToSubmitSeconds = metrics.turnstileElapsedSeconds;

      if (elapsedSeconds < 1.5) {
        rawScore += 35;
        reasons.push(
          `HIGH_VELOCITY: Submitted in ${elapsedSeconds.toFixed(1)}s after challenge (+35)`
        );
      } else if (elapsedSeconds < 3.0) {
        rawScore += 15;
        reasons.push(
          `FAST_SUBMISSION: Submitted in ${elapsedSeconds.toFixed(1)}s after challenge (+15)`
        );
      }
    } catch {
      // Ignore timestamp parse errors
    }
  }

  // 3. Turnstile Bot Score Alignment (if Enterprise / Bot Management is enabled)
  if (options.turnstileResult?.score !== undefined) {
    const tScore = options.turnstileResult.score;
    metrics.turnstileScore = tScore;

    if (tScore < 0.2) {
      rawScore += 35;
      reasons.push(`TURNSTILE_BOT_SCORE: Cloudflare bot score ${tScore.toFixed(2)} (+35)`);
    } else if (tScore < 0.4) {
      rawScore += 20;
      reasons.push(`TURNSTILE_BOT_SCORE: Cloudflare bot score ${tScore.toFixed(2)} (+20)`);
    } else if (tScore >= 0.85) {
      rawScore -= 15;
      reasons.push(`TURNSTILE_HUMAN_CONFIDENCE: Cloudflare bot score ${tScore.toFixed(2)} (-15)`);
    }
  }

  // Extract text fields and detect contact info
  let allText = '';
  let primaryName = '';
  let primaryEmail = '';

  for (const [key, value] of Object.entries(data)) {
    if (typeof value !== 'string') continue;
    const normKey = key.trim().toLowerCase();

    // Skip honeypot fields from general text analysis
    if (honeypotKeys.some((hp) => hp.toLowerCase() === normKey)) continue;

    if (normKey.includes('name')) {
      primaryName += ' ' + value;
    }
    if (normKey.includes('email') || value.includes('@')) {
      if (!primaryEmail && value.includes('@')) {
        primaryEmail = value.trim();
      }
    }
    allText += ' ' + value;
  }

  allText = allText.trim();

  // 4. URL in Name or Subject Field
  if (primaryName && (primaryName.includes('http://') || primaryName.includes('https://') || primaryName.includes('www.'))) {
    rawScore += 50;
    reasons.push('URL_IN_NAME: Contact name contains a URL (+50)');
  }

  // 5. Link Count and Density Analysis
  const links = allText.match(URL_REGEX) || [];
  metrics.linkCount = links.length;

  if (links.length >= 4) {
    rawScore += 45;
    reasons.push(`EXCESSIVE_LINKS: Found ${links.length} links (+45)`);
  } else if (links.length >= 2) {
    rawScore += 25;
    reasons.push(`MULTIPLE_LINKS: Found ${links.length} links (+25)`);
  } else if (links.length === 1) {
    rawScore += 10;
    reasons.push('CONTAINS_LINK: Found 1 link (+10)');
  }

  if (allText.length > 30) {
    const totalUrlChars = links.reduce((sum, url) => sum + url.length, 0);
    const density = totalUrlChars / allText.length;
    metrics.linkDensity = Number(density.toFixed(2));

    if (density > 0.4) {
      rawScore += 30;
      reasons.push(
        `HIGH_LINK_DENSITY: ${(density * 100).toFixed(0)}% of content is URLs (+30)`
      );
    }
  }

  // 6. Email & TLD Analysis
  if (primaryEmail) {
    if (isDisposableEmail(primaryEmail)) {
      metrics.disposableEmail = true;
      rawScore += 35;
      reasons.push('DISPOSABLE_EMAIL: Domain is a known burner address (+35)');
    }

    if (hasSuspiciousTld(primaryEmail)) {
      metrics.suspiciousTld = true;
      rawScore += 15;
      reasons.push('SUSPICIOUS_TLD: Email domain uses high-abuse TLD (+15)');
    }
  }

  // Check URLs for suspicious TLDs
  for (const url of links) {
    if (hasSuspiciousTld(url)) {
      metrics.suspiciousTld = true;
      rawScore += 15;
      reasons.push('SUSPICIOUS_URL_TLD: Linked domain uses high-abuse TLD (+15)');
      break;
    }
  }

  // 7. Spam Keyword & Pattern Analysis
  for (const pattern of SPAM_PATTERNS) {
    if (pattern.regex.test(allText)) {
      metrics.keywordMatches.push(pattern.name);
      rawScore += pattern.weight;
      reasons.push(`SPAM_PATTERN: Matched "${pattern.name}" (+${pattern.weight})`);
    }
  }

  // Custom Keywords
  if (options.customKeywords && options.customKeywords.length > 0) {
    for (const kw of options.customKeywords) {
      const cleanKw = kw.trim().toLowerCase();
      if (cleanKw && allText.toLowerCase().includes(cleanKw)) {
        metrics.keywordMatches.push(cleanKw);
        rawScore += 20;
        reasons.push(`CUSTOM_SPAM_KEYWORD: Matched "${cleanKw}" (+20)`);
      }
    }
  }

  // 8. Obfuscation & Oddities
  if (allText.length > 60) {
    // Excessive uppercase (ALL CAPS shouting)
    const upperCount = (allText.match(/[A-Z]/g) || []).length;
    const letterCount = (allText.match(/[a-zA-Z]/g) || []).length;
    if (letterCount > 40 && upperCount / letterCount > 0.75) {
      rawScore += 15;
      reasons.push('EXCESSIVE_CAPS: Over 75% uppercase text (+15)');
    }

    // Excessive character flood (e.g. "aaaaaaa", "!!!!!!!!!!")
    if (/(.)\1{7,}/.test(allText)) {
      rawScore += 15;
      reasons.push('CHARACTER_FLOOD: Repeated character sequence (+15)');
    }
  }

  // Clamp final score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, rawScore));
  const isSpam = finalScore >= threshold;

  return {
    engineVersion: SPAM_ENGINE_VERSION,
    score: finalScore,
    isSpam,
    threshold,
    reasons,
    metrics,
    analyzedAt: new Date().toISOString(),
  };
}

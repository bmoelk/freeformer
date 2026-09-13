import { describe, it, expect, vi } from 'vitest';
import { evaluateSpam, SPAM_ENGINE_VERSION } from './spam/detector';
import { isDisposableEmail, hasSuspiciousTld } from './spam/disposable-domains';
import { generateAndSendSpamDigest } from './spam/digest';
import { generateDigestHTML, generateDigestTEXT } from './templates';
import { type SpamDigestData } from './spam/types';

describe('FreeFormer Spam Detection Engine', () => {
  describe('Honeypot Trap Detection', () => {
    it('passes legitimate submission when honeypot fields are absent or empty', () => {
      const data = {
        name: 'Jane Doe',
        email: 'jane@example.com',
        message: 'Hello, I would like to inquire about your engineering consulting services.',
        _hp: '',
        website: '',
      };

      const result = evaluateSpam(data);
      expect(result.metrics.hasHoneypot).toBe(false);
      expect(result.score).toBeLessThan(30);
      expect(result.isSpam).toBe(false);
    });

    it('immediately flags submission when default honeypot field is populated', () => {
      const data = {
        name: 'Spam Bot',
        email: 'spambot@example.com',
        message: 'Great website! Visit our page.',
        _hp: 'http://spam-trap.com',
      };

      const result = evaluateSpam(data);
      expect(result.metrics.hasHoneypot).toBe(true);
      expect(result.metrics.honeypotFieldName).toBe('_hp');
      expect(result.score).toBeGreaterThanOrEqual(80);
      expect(result.isSpam).toBe(true);
      expect(result.reasons.some((r) => r.includes('HONEYPOT_FILLED'))).toBe(true);
    });

    it('detects alternate honeypots like website or company_url', () => {
      const data = {
        name: 'Botty',
        email: 'bot@example.com',
        website: 'https://illicit-promo.com',
        message: 'Check out this product.',
      };

      const result = evaluateSpam(data);
      expect(result.metrics.hasHoneypot).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(80);
      expect(result.isSpam).toBe(true);
    });
  });

  describe('Turnstile Velocity & Bot Score Alignment', () => {
    it('penalizes sub-second submission velocity', () => {
      const now = Date.now();
      const challengeTs = new Date(now - 800).toISOString(); // 0.8s elapsed

      const result = evaluateSpam(
        { name: 'Fast Submitter', email: 'fast@example.com', message: 'Hello there' },
        {
          turnstileResult: { success: true, challenge_ts: challengeTs },
          requestTimestamp: now,
        }
      );

      expect(result.metrics.turnstileElapsedSeconds).toBeLessThan(1.5);
      expect(result.reasons.some((r) => r.includes('HIGH_VELOCITY'))).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(35);
    });

    it('incorporates Turnstile bot score penalties and human bonuses', () => {
      // Very low score (likely bot)
      const botResult = evaluateSpam(
        { name: 'Bot User', email: 'bot@example.com', message: 'Hi' },
        { turnstileResult: { success: true, score: 0.1 } }
      );
      expect(botResult.score).toBeGreaterThanOrEqual(35);
      expect(botResult.reasons.some((r) => r.includes('TURNSTILE_BOT_SCORE'))).toBe(true);

      // High confidence human score
      const humanResult = evaluateSpam(
        { name: 'Alex Human', email: 'alex@example.com', message: 'Legitimate message about your products.' },
        { turnstileResult: { success: true, score: 0.95 } }
      );
      expect(humanResult.reasons.some((r) => r.includes('TURNSTILE_HUMAN_CONFIDENCE'))).toBe(true);
      expect(humanResult.score).toBe(0);
      expect(humanResult.isSpam).toBe(false);
    });
  });

  describe('Link Density & Obfuscation Analysis', () => {
    it('penalizes URLs embedded inside contact name', () => {
      const data = {
        name: 'Casino Online https://super-slots.com',
        email: 'slots@example.com',
        message: 'Play now and win big money today!',
      };

      const result = evaluateSpam(data);
      expect(result.reasons.some((r) => r.includes('URL_IN_NAME'))).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(60);
      expect(result.isSpam).toBe(true);
    });

    it('penalizes messages with high link counts and high link density', () => {
      const data = {
        name: 'Link Spammer',
        email: 'spammer@example.com',
        message: 'Check https://site1.com and https://site2.com and https://site3.com and https://site4.com for info!',
      };

      const result = evaluateSpam(data);
      expect(result.metrics.linkCount).toBe(4);
      expect(result.score).toBeGreaterThanOrEqual(60);
      expect(result.isSpam).toBe(true);
    });
  });

  describe('Disposable Emails & Suspicious TLDs', () => {
    it('identifies known temporary / burner email domains', () => {
      expect(isDisposableEmail('test@mailinator.com')).toBe(true);
      expect(isDisposableEmail('anon@10minutemail.com')).toBe(true);
      expect(isDisposableEmail('user@tempmail.net')).toBe(true);
      expect(isDisposableEmail('brian@brainendeavor.com')).toBe(false);
      expect(isDisposableEmail('contact@splitphase.io')).toBe(false);
    });

    it('identifies high-abuse TLDs', () => {
      expect(hasSuspiciousTld('spammer@domain.xyz')).toBe(true);
      expect(hasSuspiciousTld('bot@phishing.ru')).toBe(true);
      expect(hasSuspiciousTld('https://cheap-deals.click')).toBe(true);
      expect(hasSuspiciousTld('user@gmail.com')).toBe(false);
      expect(hasSuspiciousTld('brian@splitphase.io')).toBe(false);
    });

    it('adds score penalties for burner emails and suspicious TLDs', () => {
      const data = {
        name: 'Burner User',
        email: 'attacker@mailinator.com',
        message: 'Inquiry from your website.',
      };

      const result = evaluateSpam(data);
      expect(result.metrics.disposableEmail).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(35);
      expect(result.reasons.some((r) => r.includes('DISPOSABLE_EMAIL'))).toBe(true);
    });
  });

  describe('Spam Keywords & Categorized Patterns', () => {
    it('flags SEO backlink pitches', () => {
      const data = {
        name: 'SEO Marketer',
        email: 'outreach@seo-agency.com',
        message: 'Hello, I was checking your website and noticed you need high authority backlinks and guest posts to reach the first page of Google.',
      };

      const result = evaluateSpam(data);
      expect(result.metrics.keywordMatches.length).toBeGreaterThan(0);
      expect(result.score).toBeGreaterThanOrEqual(50);
      expect(result.reasons.some((r) => r.includes('SEO Backlinks'))).toBe(true);
    });

    it('flags crypto recovery and wallet validation scams', () => {
      const data = {
        name: 'Crypto Helper',
        email: 'support@wallet-support.com',
        message: 'URGENT: Connect your wallet to validate your account and receive your airdrop tokens USDT bonus.',
      };

      const result = evaluateSpam(data);
      expect(result.score).toBeGreaterThanOrEqual(60);
      expect(result.isSpam).toBe(true);
    });

    it('flags extortion and fake copyright threats', () => {
      const data = {
        name: 'Legal Copyright Notice',
        email: 'attorney@law-firm.com',
        message: 'You have committed a copyright infringement on your website. Legal action will be taken against you immediately if not resolved.',
      };

      const result = evaluateSpam(data);
      expect(result.reasons.some((r) => r.includes('Fake DMCA & Copyright Threat'))).toBe(true);
    });

    it('flags Telegram and WhatsApp redirect traps', () => {
      const data = {
        name: 'Signal Provider',
        email: 'invest@gmail.com',
        message: 'Join our daily VIP signals group at t.me/bestcryptosignals for 500% profit.',
      };

      const result = evaluateSpam(data);
      expect(result.reasons.some((r) => r.includes('Telegram or WhatsApp Chat Trap'))).toBe(true);
    });

    it('supports custom site-specific keywords', () => {
      const data = {
        name: 'Alex',
        email: 'alex@example.com',
        message: 'We offer special web scraping services for your site.',
      };

      const result = evaluateSpam(data, {
        customKeywords: ['web scraping', 'scraping services'],
      });

      expect(result.reasons.some((r) => r.includes('CUSTOM_SPAM_KEYWORD'))).toBe(true);
    });
  });

  describe('Engine Versioning & Threshold Customization', () => {
    it('attaches the engine version and complete telemetry', () => {
      const result = evaluateSpam({ name: 'Test', email: 'test@example.com', message: 'Hello' });
      expect(result.engineVersion).toBe(SPAM_ENGINE_VERSION);
      expect(result.engineVersion).toBe('1.0.0');
      expect(result.analyzedAt).toBeDefined();
      expect(typeof result.score).toBe('number');
      expect(typeof result.isSpam).toBe('boolean');
      expect(result.metrics).toBeDefined();
    });

    it('respects custom threshold settings', () => {
      const data = {
        name: 'Mild Marketer',
        email: 'mild@example.com',
        message: 'Check out this 1 link at https://example.com/info',
      };

      // Default threshold is 60 -> mild link scores ~10 -> clean
      const defaultResult = evaluateSpam(data, { threshold: 60 });
      expect(defaultResult.isSpam).toBe(false);

      // Aggressive threshold of 10 -> marked as spam
      const aggressiveResult = evaluateSpam(data, { threshold: 10 });
      expect(aggressiveResult.isSpam).toBe(true);
    });
  });

  describe('Spam Digest & Zero-Noise Guarantee', () => {
    it('suppresses digest email when no spam submissions were detected (Zero-Noise)', async () => {
      const mockDb = {
        prepare: () => ({
          bind: () => ({
            all: async () => ({
              results: [
                {
                  id: 'sub_1',
                  form_id: 'contact',
                  site_id: 'splitphase.io',
                  data: JSON.stringify({ name: 'Good User', email: 'good@example.com' }),
                  metadata: JSON.stringify({ isSpam: false }),
                  created_at: new Date().toISOString(),
                },
              ],
            }),
          }),
        }),
      };

      const emailConfig: any = { provider: 'console', to: 'alerts@example.com' };
      const result = await generateAndSendSpamDigest({ db: mockDb as any }, emailConfig, { days: 7 });

      expect(result.sent).toBe(false);
      expect(result.reason).toBe('no_spam');
      expect(result.count).toBe(0);
    });

    it('generates digest data and formats templates when spam exists', async () => {
      const spamSub = {
        id: 'sub_spam_99',
        formId: 'contact',
        siteId: 'splitphase.io',
        timestamp: 'Sep 13, 10:00 AM',
        senderName: 'Spam Bot',
        senderEmail: 'spambot@mailinator.com',
        score: 85,
        topReason: 'HONEYPOT_FILLED (+80)',
        snippet: 'Visit https://crypto-trap.xyz for free money...',
      };

      const digestData: SpamDigestData = {
        periodStart: 'Sep 6',
        periodEnd: 'Sep 13, 2026',
        totalSubmissions: 10,
        spamSubmissions: 2,
        cleanSubmissions: 8,
        spamPercentage: '20.0%',
        items: [spamSub],
        adminUrl: 'https://freeformer.example.com/admin?filter=spam',
      };

      const html = generateDigestHTML(digestData);
      expect(html).toContain('FreeFormer Spam Digest');
      expect(html).toContain('spambot@mailinator.com');
      expect(html).toContain('HONEYPOT_FILLED (+80)');
      expect(html).toContain('85');

      const text = generateDigestTEXT(digestData);
      expect(text).toContain('FREEFORMER SPAM DIGEST');
      expect(text).toContain('Quarantined Spam: 2');
      expect(text).toContain('spambot@mailinator.com');
    });
  });
});

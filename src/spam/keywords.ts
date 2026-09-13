/**
 * FreeFormer Spam Keywords & Pattern Definitions
 * Categorized and weighted pattern matching for contact form spam.
 */

export interface SpamPattern {
  name: string;
  category: 'seo' | 'crypto' | 'phishing' | 'pharma_adult' | 'shortener' | 'markup';
  weight: number;
  regex: RegExp;
}

export const SPAM_PATTERNS: SpamPattern[] = [
  // 1. SEO & Marketing Spam
  {
    name: 'SEO Backlinks & Guest Posts',
    category: 'seo',
    weight: 25,
    regex: /\b(backlinks?|guest\s*posts?|link\s*building|pbn\s*links?|dofollow|da\s*[0-9]{2}\+|high\s*authority\s*links?)\b/i,
  },
  {
    name: 'Google Ranking Pitches',
    category: 'seo',
    weight: 25,
    regex: /\b(first\s*page\s*of\s*google|rank\s*#?1\s*on\s*google|google\s*rankings?|organic\s*traffic\s*growth|seo\s*audit|improve\s*(your\s*)?seo)\b/i,
  },
  {
    name: 'Cold Outreach & B2B Lead Lists',
    category: 'seo',
    weight: 20,
    regex: /\b(b2b\s*leads?|targeted\s*email\s*list|outsource\s*(your\s*)?(web|app|software)|white\s*label\s*seo)\b/i,
  },

  // 2. Crypto, Forex & Financial Scams
  {
    name: 'Crypto & Wallet Scams',
    category: 'crypto',
    weight: 35,
    regex: /\b(crypto\s*invest(ment)?|bitcoin\s*recov(ery|er)|wallet\s*connect|validate\s*(your\s*)?wallet|airdrop\s*tokens?|usdt\s*bonus|doubling\s*btc|binance\s*reward)\b/i,
  },
  {
    name: 'Forex & Guaranteed Wealth',
    category: 'crypto',
    weight: 30,
    regex: /\b(forex\s*trading|trading\s*signals?|passive\s*income\s*guaranteed|daily\s*profits?|make\s*\$?[0-9,]+\s*daily)\b/i,
  },

  // 3. Phishing, Extortion & Fake Legal Notices
  {
    name: 'Fake DMCA & Copyright Threat',
    category: 'phishing',
    weight: 35,
    regex: /\b(copyright\s*infringement|dmca\s*violation|legal\s*action\s*(will\s*be\s*taken|against\s*you)|unauthorized\s*use\s*of\s*(my\s*)?images?|intellectual\s*property\s*violation)\b/i,
  },
  {
    name: 'Account Suspension Urgency',
    category: 'phishing',
    weight: 30,
    regex: /\b(urg(?:ent|ency)|immediate\s*action\s*required|verify\s*your\s*account\s*now|security\s*alert\s*notice|account\s*(will\s*be\s*)?suspend(ed)?)\b/i,
  },

  // 4. Pharma, Casino & Adult
  {
    name: 'Pharma Spam',
    category: 'pharma_adult',
    weight: 35,
    regex: /\b(viagra|cialis|levitra|pharmacy\s*online|no\s*prescription\s*required|phentermine)\b/i,
  },
  {
    name: 'Casino & Gambling',
    category: 'pharma_adult',
    weight: 30,
    regex: /\b((online\s+)?casino(\s+online)?|slot\s*machines?|free\s*spins|betting\s*bonus|poker\s*rooms?)\b/i,
  },
  {
    name: 'Adult & Escort',
    category: 'pharma_adult',
    weight: 35,
    regex: /\b(escort\s*service|adult\s*dating|hookup\s*now|meet\s*singles\s*tonight|webcam\s*models?)\b/i,
  },

  // 5. Shorteners & Chat Redirects
  {
    name: 'Telegram or WhatsApp Chat Trap',
    category: 'shortener',
    weight: 25,
    regex: /\b(t\.me\/[a-zA-Z0-9_+]+|wa\.me\/[0-9]+|chat\.whatsapp\.com\/[a-zA-Z0-9]+)\b/i,
  },
  {
    name: 'URL Shortener in Message',
    category: 'shortener',
    weight: 20,
    regex: /\b(bit\.ly|tinyurl\.com|cutt\.ly|is\.gd|rb\.gy|ow\.ly|t\.co)\/[a-zA-Z0-9_-]+\b/i,
  },

  // 6. BBCode & Raw HTML Injections
  {
    name: 'BBCode / HTML Tag Injection',
    category: 'markup',
    weight: 25,
    regex: /(\[url=[^\]]+\]|<a\s+href=|<script\b|\[link=[^\]]+\])/i,
  },
];

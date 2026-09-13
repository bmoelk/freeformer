/**
 * FreeFormer Disposable Email Domains & Suspicious TLDs
 */

export const DISPOSABLE_EMAIL_DOMAINS = new Set([
  '10minutemail.com',
  '10minutemail.net',
  '20minutemail.com',
  'burnermail.io',
  'dispostable.com',
  'dropmail.me',
  'fakeinbox.com',
  'fakemailgenerator.com',
  'generator.email',
  'getairmail.com',
  'guerrillamail.biz',
  'guerrillamail.com',
  'guerrillamail.de',
  'guerrillamail.net',
  'guerrillamail.org',
  'inboxkitten.com',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailnesia.com',
  'mohmal.com',
  'nada.ltd',
  'sharklasers.com',
  'spam4.me',
  'spambox.us',
  'temp-mail.org',
  'tempail.com',
  'tempmail.com',
  'tempmail.net',
  'throwawaymail.com',
  'trashmail.com',
  'trashmail.net',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
  'crazymailing.com',
  'mailpoof.com',
  'mytemp.email',
]);

export const SUSPICIOUS_TLDS = new Set([
  'ru',
  'top',
  'xyz',
  'buzz',
  'click',
  'surf',
  'work',
  'link',
  'gq',
  'cf',
  'ml',
  'tk',
  'ga',
]);

/**
 * Check if domain or email address uses a disposable domain
 */
export function isDisposableEmail(email: string): boolean {
  if (!email || !email.includes('@')) return false;
  const domain = email.split('@').pop()?.trim().toLowerCase();
  if (!domain) return false;
  return DISPOSABLE_EMAIL_DOMAINS.has(domain);
}

/**
 * Check if domain uses a high-abuse / suspicious TLD
 */
export function hasSuspiciousTld(emailOrUrl: string): boolean {
  if (!emailOrUrl) return false;
  const cleaned = emailOrUrl.toLowerCase().trim();
  let domain = cleaned;

  if (cleaned.includes('@')) {
    domain = cleaned.split('@').pop() || '';
  } else if (cleaned.startsWith('http://') || cleaned.startsWith('https://')) {
    try {
      domain = new URL(cleaned).hostname;
    } catch {
      // ignore
    }
  }

  const parts = domain.split('.');
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1];
  return SUSPICIOUS_TLDS.has(tld);
}

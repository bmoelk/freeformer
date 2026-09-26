/**
 * Email Address Formatting & Parsing Utilities
 */

export interface ParsedEmailAddress {
  address: string;
  name?: string;
}

/**
 * Parse an email string into address and optional display name.
 * Handles formats like:
 *   - "user@example.com"
 *   - "John Doe <user@example.com>"
 *   - "\"John Doe\" <user@example.com>"
 */
export function parseEmailAddress(input: string): ParsedEmailAddress {
  const trimmed = input.trim();
  const match = trimmed.match(/^(?:(.*?)<)?([^<>]+)>?$/);
  if (match && match[1]) {
    const name = match[1].trim().replace(/^["']|["']$/g, '');
    const address = match[2].trim();
    return name ? { address, name } : { address };
  }
  return { address: trimmed };
}

/**
 * Parses a comma-separated list of email recipients.
 * Empty or whitespace-only elements are filtered out.
 */
export function parseEmailList(input: string): ParsedEmailAddress[] {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map(parseEmailAddress);
}

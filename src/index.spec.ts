import { describe, it, expect } from 'vitest';
import { getSiteEnvVariants, resolveSiteEnv } from './index';
import { matchesPattern, isFieldProtected, sanitizeSubmissionData } from './templates';
import {
    sanitizeFilename,
    validateAttachment,
    createSignedDownloadUrl,
    verifySignedDownloadToken,
} from './files';
import { buildWebhookPayload, signWebhookPayload } from './webhook';
import { verifyTurnstile } from './turnstile';

describe('FreeFormer Unit Tests', () => {
    describe('getSiteEnvVariants', () => {
        it('resolves site-specific variants correctly', () => {
            const variants = getSiteEnvVariants('TURNSTILE_SITE_KEY', 'splitphase.io');
            expect(variants).toContain('TURNSTILE_SITE_KEY_SPLITPHASE_IO');
            expect(variants).toContain('TURNSTILE_SITE_KEY_SPLITPHASEIO');
            expect(variants).toContain('TURNSTILE_SITE_KEY_SPLITPHASE');
            expect(variants).toContain('TURNSTILE_SITE_KEY');
        });

        it('handles simple site identifiers without dots', () => {
            const variants = getSiteEnvVariants('EMAIL_TO', 'brainendeavor');
            expect(variants).toContain('EMAIL_TO_BRAINENDEAVOR');
            expect(variants).toContain('EMAIL_TO');
        });
    });

    describe('resolveSiteEnv', () => {
        it('prefers exact site match over global fallback', () => {
            const env = {
                EMAIL_TO: 'global@example.com',
                EMAIL_TO_BRAINENDEAVOR: 'brian@brainendeavor.com',
            };
            const result = resolveSiteEnv(env, 'EMAIL_TO', 'brainendeavor');
            expect(result).toBe('brian@brainendeavor.com');
        });

        it('falls back to global variable when site variable is absent', () => {
            const env = {
                EMAIL_TO: 'global@example.com',
            };
            const result = resolveSiteEnv(env, 'EMAIL_TO', 'other-site');
            expect(result).toBe('global@example.com');
        });
    });

    describe('Protected Fields Sanitization', () => {
        it('matches exact patterns case-insensitively', () => {
            expect(matchesPattern('ssn', 'ssn')).toBe(true);
            expect(matchesPattern('SSN', 'ssn')).toBe(true);
            expect(matchesPattern('tax_id', 'TAX_ID')).toBe(true);
            expect(matchesPattern('email', 'ssn')).toBe(false);
        });

        it('matches wildcard patterns correctly', () => {
            expect(matchesPattern('utm_source', 'utm_*')).toBe(true);
            expect(matchesPattern('UTM_MEDIUM', 'utm_*')).toBe(true);
            expect(matchesPattern('internal_token', '*_token')).toBe(true);
            expect(matchesPattern('normal_field', 'utm_*')).toBe(false);
        });

        it('filters out system keys and protected fields from email template fields', () => {
            const data = {
                name: 'Jane Doe',
                email: 'jane@example.com',
                ssn: '123-45-6789',
                utm_source: 'google',
                utm_campaign: 'spring_sale',
                turnstileToken: 'token123',
                message: 'Hello world',
            };

            const fields = sanitizeSubmissionData(data, ['ssn', 'utm_*']);
            const fieldKeys = fields.map((f: { key: string }) => f.key);

            expect(fieldKeys).toContain('name');
            expect(fieldKeys).toContain('email');
            expect(fieldKeys).toContain('message');
            expect(fieldKeys).not.toContain('ssn');
            expect(fieldKeys).not.toContain('utm_source');
            expect(fieldKeys).not.toContain('utm_campaign');
            expect(fieldKeys).not.toContain('turnstileToken');
        });
    });

    describe('R2 File Attachment Security', () => {
        it('sanitizes filenames into clean URL-safe slugs', () => {
            const result = sanitizeFilename('Project Brief & Notes (Final).PDF');
            expect(result.filename).toBe('project-brief-notes-final.pdf');
            expect(result.ext).toBe('pdf');
        });

        it('rejects disallowed executable or script extensions', () => {
            const fakeExe = { name: 'malware.exe', size: 1024 } as File;
            const resExe = validateAttachment(fakeExe);
            expect(resExe.valid).toBe(false);
            expect(resExe.error).toContain('not permitted for security reasons');

            const fakeHtml = { name: 'exploit.html', size: 1024 } as File;
            const resHtml = validateAttachment(fakeHtml);
            expect(resHtml.valid).toBe(false);
        });

        it('rejects files that exceed maximum size', () => {
            const bigFile = { name: 'video.mp4', size: 25 * 1024 * 1024 } as File;
            const res = validateAttachment(bigFile, 10 * 1024 * 1024);
            expect(res.valid).toBe(false);
            expect(res.error).toContain('exceeds maximum allowed size');
        });
    });

    describe('Signed R2 URLs & Universal Webhook', () => {
        it('generates and verifies HMAC signed download URLs', async () => {
            const secret = 'test-secret-key-12345';
            const key = 'splitphase.io/contact/sub_1/resume.pdf';
            const url = await createSignedDownloadUrl('https://example.com', key, secret, 60);

            expect(url).toContain('/files/signed?key=');
            expect(url).toContain('token=');
            expect(url).toContain('expires=');

            const parsed = new URL(url);
            const token = parsed.searchParams.get('token')!;
            const expires = parsed.searchParams.get('expires')!;

            const valid = await verifySignedDownloadToken(key, expires, token, secret);
            expect(valid).toBe(true);

            // Fails on wrong secret
            const invalidSecret = await verifySignedDownloadToken(key, expires, token, 'wrong-secret');
            expect(invalidSecret).toBe(false);

            // Fails on expired timestamp
            const expired = await verifySignedDownloadToken(key, '1000000000', token, secret);
            expect(expired).toBe(false);
        });

        it('builds universal webhook payload with signed attachments', async () => {
            const secret = 'webhook-secret-xyz';
            const submission = {
                submissionId: 'sub_test_99',
                formId: 'inquiry',
                siteId: 'splitphase.io',
                data: { name: 'Alex', email: 'alex@example.com' },
                metadata: {
                    ip: '1.2.3.4',
                    userAgent: 'TestBrowser',
                    timestamp: new Date().toISOString(),
                    turnstileScore: 0.9,
                },
                attachments: [
                    {
                        filename: 'resume.pdf',
                        key: 'splitphase.io/inquiry/sub_test_99/resume.pdf',
                        size: 5000,
                        mimeType: 'application/pdf',
                        uploadedAt: new Date().toISOString(),
                    },
                ],
            };

            const payload = await buildWebhookPayload(submission, 'https://myworker.dev', secret, 600);

            expect(payload.event).toBe('form_submission');
            expect(payload.id).toBe('sub_test_99');
            expect(payload.data.name).toBe('Alex');
            expect(payload.attachments.length).toBe(1);
            expect(payload.attachments[0].downloadUrl).toContain('/files/signed?key=');

            const signature = await signWebhookPayload(JSON.stringify(payload), secret);
            expect(typeof signature).toBe('string');
            expect(signature.length).toBe(64); // SHA-256 hex string length
        });
    });

    describe('verifyTurnstile', () => {
        it('passes in dev mock mode', async () => {
            const result = await verifyTurnstile('dev', '', '', true);
            expect(result.success).toBe(true);
            expect(result.score).toBe(1.0);
        });

        it('rejects "dev" token in production mode', async () => {
            const result = await verifyTurnstile('dev', 'some-secret-key', '1.2.3.4', false);
            expect(result.success).toBe(false);
            expect(result.errors).toContain('invalid-input-response');
        });

        it('rejects verification when secret key is missing in production', async () => {
            const result = await verifyTurnstile('real-or-test-token', '', '1.2.3.4', false);
            expect(result.success).toBe(false);
            expect(result.errors).toContain('missing-secret-key');
        });

        it('passes Cloudflare official test dummy key combination', async () => {
            const result = await verifyTurnstile(
                '1x00000000000000000000AA',
                '1x00000000000000000000AA00000000000',
                '1.2.3.4',
                false
            );
            expect(result.success).toBe(true);
            expect(result.score).toBe(1.0);
        });
    });
});

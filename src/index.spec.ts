import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getSiteEnvVariants, resolveSiteEnv, app } from './index';
import { matchesPattern, isFieldProtected, sanitizeSubmissionData } from './templates';
import {
    sanitizeFilename,
    validateAttachment,
    createSignedDownloadUrl,
    verifySignedDownloadToken,
} from './files';
import { buildWebhookPayload, signWebhookPayload } from './webhook';
import { verifyTurnstile } from './turnstile';
import {
    parseEmailAddress,
    parseEmailList,
    sendViaZoho,
    sendRawEmail,
    getEmailAdapter,
    registerEmailAdapter,
    ConsoleEmailAdapter,
    ResendEmailAdapter,
    SendGridEmailAdapter,
    MailgunEmailAdapter,
    MailtrapEmailAdapter,
    ZohoEmailAdapter,
    type EmailConfig,
    type RawEmailPayload,
    type EmailAdapter,
} from './email';

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

    describe('Zoho CPaaS Email Provider', () => {
        const originalFetch = globalThis.fetch;

        afterEach(() => {
            globalThis.fetch = originalFetch;
            vi.restoreAllMocks();
        });

        describe('parseEmailAddress', () => {
            it('parses plain email address', () => {
                const parsed = parseEmailAddress('user@example.com');
                expect(parsed).toEqual({ address: 'user@example.com' });
            });

            it('parses email address with display name', () => {
                const parsed = parseEmailAddress('Brian M <brian@example.com>');
                expect(parsed).toEqual({ address: 'brian@example.com', name: 'Brian M' });
            });

            it('parses quoted display names', () => {
                const parsed = parseEmailAddress('"Support Team" <support@example.com>');
                expect(parsed).toEqual({ address: 'support@example.com', name: 'Support Team' });
            });
        });

        describe('sendViaZoho', () => {
            it('sends email to default endpoint with correctly structured body and Zoho-enczapikey header', async () => {
                let capturedUrl = '';
                let capturedOptions: any = {};

                globalThis.fetch = vi.fn().mockImplementation(async (url: string, opts: any) => {
                    capturedUrl = url;
                    capturedOptions = opts;
                    return new Response(JSON.stringify({
                        data: [{ code: 'EM_104', message: 'OK' }],
                        message: 'OK',
                        request_id: 'req-123'
                    }), { status: 200 });
                });

                const config: EmailConfig = {
                    provider: 'zoho',
                    apiKey: 'test-api-key-123',
                    from: 'FreeFormer <noreply@splitphase.io>',
                    to: 'brian@dailyreprieve.com, alerts@splitphase.io',
                };

                const payload: RawEmailPayload = {
                    subject: 'Test Form Submission',
                    html: '<p>Hello world</p>',
                    text: 'Hello world',
                };

                const result = await sendViaZoho(config, payload);

                expect(result.success).toBe(true);
                expect(capturedUrl).toBe('https://cpaas.zoho.com/v1.1/email');
                expect(capturedOptions.method).toBe('POST');
                expect(capturedOptions.headers['Authorization']).toBe('Zoho-enczapikey test-api-key-123');
                expect(capturedOptions.headers['Content-Type']).toBe('application/json');

                const parsedBody = JSON.parse(capturedOptions.body);
                expect(parsedBody.from).toEqual({ address: 'noreply@splitphase.io', name: 'FreeFormer' });
                expect(parsedBody.to).toEqual([
                    { email_address: { address: 'brian@dailyreprieve.com' } },
                    { email_address: { address: 'alerts@splitphase.io' } },
                ]);
                expect(parsedBody.subject).toBe('Test Form Submission');
                expect(parsedBody.htmlbody).toBe('<p>Hello world</p>');
                expect(parsedBody.textbody).toBe('Hello world');
            });

            it('does not duplicate Zoho-enczapikey if already prefixed', async () => {
                let authHeader = '';

                globalThis.fetch = vi.fn().mockImplementation(async (_url: string, opts: any) => {
                    authHeader = opts.headers['Authorization'];
                    return new Response(JSON.stringify({ message: 'OK' }), { status: 200 });
                });

                const config: EmailConfig = {
                    provider: 'zoho',
                    apiKey: 'Zoho-enczapikey pre-prefixed-token-xyz',
                    from: 'noreply@example.com',
                    to: 'admin@example.com',
                };

                const result = await sendViaZoho(config, {
                    subject: 'Subject',
                    html: '<p>Test</p>',
                    text: 'Test',
                });

                expect(result.success).toBe(true);
                expect(authHeader).toBe('Zoho-enczapikey pre-prefixed-token-xyz');
            });

            it('supports custom zohoApiUrl override (e.g. ZeptoMail regional endpoint)', async () => {
                let capturedUrl = '';

                globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
                    capturedUrl = url;
                    return new Response(JSON.stringify({ message: 'OK' }), { status: 200 });
                });

                const config: EmailConfig = {
                    provider: 'zoho',
                    apiKey: 'key',
                    from: 'noreply@example.com',
                    to: 'admin@example.com',
                    zohoApiUrl: 'https://api.zeptomail.eu/v1.1/email',
                };

                const result = await sendViaZoho(config, {
                    subject: 'Regional Test',
                    html: '<p>EU</p>',
                    text: 'EU',
                });

                expect(result.success).toBe(true);
                expect(capturedUrl).toBe('https://api.zeptomail.eu/v1.1/email');
            });

            it('handles API error responses and extracts structured error codes', async () => {
                globalThis.fetch = vi.fn().mockImplementation(async () => {
                    return new Response(JSON.stringify({
                        data: {
                            error_code: 'TM_3004',
                            message: 'Invalid request: from address not verified'
                        },
                        message: 'error'
                    }), { status: 400 });
                });

                const config: EmailConfig = {
                    provider: 'zoho',
                    apiKey: 'key',
                    from: 'unverified@example.com',
                    to: 'admin@example.com',
                };

                const result = await sendViaZoho(config, {
                    subject: 'Subject',
                    html: 'html',
                    text: 'text',
                });

                expect(result.success).toBe(false);
                expect(result.error).toContain('Zoho error (400)');
                expect(result.error).toContain('Invalid request: from address not verified (TM_3004)');
            });
        });

        describe('sendRawEmail provider dispatch', () => {
            it('routes zoho, zoho_cpaas, and zeptomail providers to sendViaZoho', async () => {
                const fetchMock = vi.fn().mockImplementation(async () =>
                    new Response(JSON.stringify({ message: 'OK' }), { status: 200 })
                );
                globalThis.fetch = fetchMock;

                const payload: RawEmailPayload = {
                    subject: 'Subject',
                    html: 'html',
                    text: 'text',
                };

                for (const provider of ['zoho', 'zoho_cpaas', 'zeptomail'] as const) {
                    const res = await sendRawEmail({
                        provider,
                        apiKey: 'key-123',
                        from: 'from@example.com',
                        to: 'to@example.com',
                    }, payload);

                    expect(res.success).toBe(true);
                }

                expect(fetchMock).toHaveBeenCalledTimes(3);
            });
        });
    });

    describe('Polymorphic Email Adapter Architecture', () => {
        describe('parseEmailList', () => {
            it('parses multiple comma-separated emails with mixed formats', () => {
                const list = parseEmailList('alice@example.com, Bob <bob@example.com>, "Charlie D" <charlie@example.com>');
                expect(list).toEqual([
                    { address: 'alice@example.com' },
                    { address: 'bob@example.com', name: 'Bob' },
                    { address: 'charlie@example.com', name: 'Charlie D' },
                ]);
            });

            it('filters out empty or whitespace entries', () => {
                const list = parseEmailList('  ,  user@example.com , , ');
                expect(list).toEqual([{ address: 'user@example.com' }]);
            });
        });

        describe('Adapter Registry & Factory', () => {
            it('resolves correct adapter instance for each supported provider', () => {
                const baseConfig: EmailConfig = {
                    provider: 'console',
                    apiKey: 'test-key',
                    from: 'from@example.com',
                    to: 'to@example.com',
                };

                expect(getEmailAdapter({ ...baseConfig, provider: 'console' })).toBeInstanceOf(ConsoleEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'resend' })).toBeInstanceOf(ResendEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'sendgrid' })).toBeInstanceOf(SendGridEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'mailgun' })).toBeInstanceOf(MailgunEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'mailtrap' })).toBeInstanceOf(MailtrapEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'zoho' })).toBeInstanceOf(ZohoEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'zoho_cpaas' })).toBeInstanceOf(ZohoEmailAdapter);
                expect(getEmailAdapter({ ...baseConfig, provider: 'zeptomail' })).toBeInstanceOf(ZohoEmailAdapter);
            });

            it('returns null for unknown provider', () => {
                const adapter = getEmailAdapter({
                    provider: 'unsupported' as any,
                    apiKey: 'key',
                    from: 'a@b.com',
                    to: 'c@d.com',
                });
                expect(adapter).toBeNull();
            });

            it('allows registering custom email adapters', async () => {
                class MockCustomAdapter implements EmailAdapter {
                    readonly name = 'custom_mock';
                    async send(_payload: RawEmailPayload) {
                        return { success: true };
                    }
                }

                registerEmailAdapter('custom_mock', (_cfg) => new MockCustomAdapter());

                const adapter = getEmailAdapter({
                    provider: 'custom_mock' as any,
                    apiKey: 'key',
                    from: 'a@b.com',
                    to: 'c@d.com',
                });

                expect(adapter).toBeInstanceOf(MockCustomAdapter);
                const res = await adapter!.send({ subject: 's', html: 'h', text: 't' });
                expect(res.success).toBe(true);
            });
        });

        describe('sendRawEmail edge cases', () => {
            it('returns success and skips dispatch when provider is "none"', async () => {
                const res = await sendRawEmail({
                    provider: 'none',
                    apiKey: '',
                    from: '',
                    to: '',
                }, { subject: 's', html: 'h', text: 't' });
                expect(res.success).toBe(true);
            });

            it('returns error when unknown email provider is configured', async () => {
                const res = await sendRawEmail({
                    provider: 'bogus_provider' as any,
                    apiKey: 'key',
                    from: 'from@example.com',
                    to: 'to@example.com',
                }, { subject: 's', html: 'h', text: 't' });
                expect(res.success).toBe(false);
                expect(res.error).toContain('Unknown email provider');
            });

            it('skips dispatch when non-console provider is missing apiKey or to', async () => {
                const res = await sendRawEmail({
                    provider: 'resend',
                    apiKey: '',
                    from: 'from@example.com',
                    to: 'to@example.com',
                }, { subject: 's', html: 'h', text: 't' });
                expect(res.success).toBe(true);
            });
        });
    });

    describe('Spam Configuration Environment Resolution', () => {
        it('resolves site-specific SPAM_CATEGORIES overrides', () => {
            const env = {
                SPAM_CATEGORIES: 'all',
                SPAM_CATEGORIES_SPLITPHASE_IO: 'crypto,phishing',
            };
            const splitphaseCategories = resolveSiteEnv(env, 'SPAM_CATEGORIES', 'splitphase.io');
            expect(splitphaseCategories).toBe('crypto,phishing');

            const fallbackCategories = resolveSiteEnv(env, 'SPAM_CATEGORIES', 'otherdomain.com');
            expect(fallbackCategories).toBe('all');
        });

        it('resolves site-specific SPAM_DIGEST_MODE overrides', () => {
            const env = {
                SPAM_DIGEST_MODE: 'comprehensive',
                SPAM_DIGEST_MODE_QUIET_COM: 'spam_only',
            };
            const quietMode = resolveSiteEnv(env, 'SPAM_DIGEST_MODE', 'quiet.com');
            expect(quietMode).toBe('spam_only');

            const defaultMode = resolveSiteEnv(env, 'SPAM_DIGEST_MODE', 'other.com');
            expect(defaultMode).toBe('comprehensive');
        });
    });

    describe('Root Diagnostic Health Endpoint (GET /)', () => {
        it('reports SYS1POP in configuredKeys and sys1popConfigured when provided as string URL', async () => {
            const mockEnv = {
                SYS1POP: 'sys1pop.brainendeavor.com',
                SYS1POP_MODEL: 'spam-detector-v1',
                SYS1POP_API_TOKEN: 'test-token',
            };
            const res = await app.request('/', {}, mockEnv);
            expect(res.status).toBe(200);
            const body = await res.json() as any;
            expect(body.config.sys1popConfigured).toBe(true);
            expect(body.config.sys1popModel).toBe('spam-detector-v1');
            expect(body.config.sys1popTokenConfigured).toBe(true);
            expect(body.config.configuredKeys).toContain('SYS1POP');
            expect(body.config.configuredKeys).toContain('SYS1POP_MODEL');
            expect(body.config.configuredKeys).toContain('SYS1POP_API_TOKEN');
        });

        it('reports SYS1POP in configuredKeys when provided as service binding', async () => {
            const mockEnv = {
                SYS1POP: { fetch: vi.fn() },
            };
            const res = await app.request('/', {}, mockEnv);
            expect(res.status).toBe(200);
            const body = await res.json() as any;
            expect(body.config.sys1popConfigured).toBe(true);
            expect(body.config.configuredKeys).toContain('SYS1POP');
        });

        it('executes live probe on GET /?probe=sys1pop without throwing 500', async () => {
            const mockEnv = {
                SYS1POP: {
                    async fetch() {
                        return new Response(
                            JSON.stringify({
                                decisions: {
                                    is_spam: { type: 'boolean', value: false, probability: 0.01 },
                                    spam_category: { type: 'choice', winner: 'legitimate_inquiry', confidence: 0.99, distribution: {} },
                                    risk_score: { type: 'score', expected_value: 1.0, distribution: [] },
                                },
                                metrics: { total_ms: 10 },
                                cached: true,
                            }),
                            { status: 200, headers: { 'Content-Type': 'application/json' } }
                        );
                    },
                },
            };
            const res = await app.request('/?probe=sys1pop', {}, mockEnv);
            expect(res.status).toBe(200);
            const body = await res.json() as any;
            expect(body.sys1popProbe).toBeDefined();
            expect(body.sys1popProbe.success).toBe(true);
            expect(body.sys1popProbe.verdict.isSpam).toBe(false);
        });

        it('executes /sys1pop-test successfully without throwing 500', async () => {
            const mockEnv = {
                SYS1POP: 'https://sys1pop.example.com',
            };
            const res = await app.request('/sys1pop-test', {}, mockEnv);
            // Since network fetch to example.com is not mocked, probe returns configured=true, success=false with 502 or error status
            expect([200, 502]).toContain(res.status);
            const body = await res.json() as any;
            expect(body.service).toBe('FreeFormer');
            expect(body.target).toBe('Sys1Pop');
            expect(body.configured).toBe(true);
        });
    });
});



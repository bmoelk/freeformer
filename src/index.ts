import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyTurnstile } from './turnstile';
import { storeSubmission, getSubmissions, getSubmission } from './storage';
import { checkRateLimit } from './ratelimit';
import { sendEmailNotification, type EmailConfig } from './email';
import { createLogger, type Logger } from './logger';

type Bindings = {
    KV?: KVNamespace;
    DB?: D1Database;
    ENVIRONMENT?: string;
    LOG_LEVEL?: string;
    STORAGE_ENGINE?: string;
    DEV_MODE?: string;
    DEV_MOCK_TURNSTILE?: string;
    TURNSTILE_SECRET_KEY?: string;
    ALLOWED_ORIGINS?: string;
    RATE_LIMIT_ENABLED?: string;
    RATE_LIMIT_REQUESTS?: string;
    RATE_LIMIT_WINDOW?: string;
    EMAIL_PROVIDER?: string;
    EMAIL_API_KEY?: string;
    EMAIL_FROM?: string;
    EMAIL_TO?: string;
    MAILGUN_DOMAIN?: string;
    MAILTRAP_INBOX_ID?: string;
    API_KEY?: string;
    WEBHOOK_URL?: string;
};

export function getSiteEnvVariants(prefix: string, siteId: string): string[] {
    const variants: string[] = [];
    if (siteId) {
        // 1. Full identifier with underscores (e.g. splitphase.io -> SPLITPHASE_IO)
        const formatted = siteId.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase().replace(/_+/g, '_').replace(/^_|_$/g, '');
        if (formatted) variants.push(`${prefix}_${formatted}`);

        // 2. Alphanumeric only (e.g. splitphase.io -> SPLITPHASEIO)
        const alphaNum = siteId.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
        if (alphaNum && !variants.includes(`${prefix}_${alphaNum}`)) {
            variants.push(`${prefix}_${alphaNum}`);
        }

        // 3. Base domain before first dot (e.g. splitphase.io -> SPLITPHASE)
        const baseDomain = siteId.split('.')[0].replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
        if (baseDomain && !variants.includes(`${prefix}_${baseDomain}`)) {
            variants.push(`${prefix}_${baseDomain}`);
        }
    }
    variants.push(prefix); // Global fallback
    return variants;
}

export function resolveSiteEnv(
    envRecord: Record<string, string | undefined>,
    prefix: string,
    siteId: string
): string | undefined {
    const keys = getSiteEnvVariants(prefix, siteId);
    for (const key of keys) {
        if (envRecord[key]) return envRecord[key];
    }
    return undefined;
}

const app = new Hono<{ Bindings: Bindings }>();

// CORS middleware with strict project-level subdomain matching and structured logging
app.use('/*', async (c, next) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);
    const rawAllowed = c.env.ALLOWED_ORIGINS || '*';
    const allowedOrigins = rawAllowed
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

    const corsMiddleware = cors({
        origin: (requestOrigin) => {
            if (!requestOrigin) return '*';
            if (allowedOrigins.includes('*')) {
                logger.debug('CORS', `ALLOWED (Wildcard *) | Origin: "${requestOrigin}"`);
                return requestOrigin;
            }

            let reqHost = '';
            try {
                reqHost = new URL(requestOrigin).hostname.toLowerCase();
            } catch {
                logger.warn('CORS', `BLOCKED (Invalid Origin URL) | Origin: "${requestOrigin}"`);
                return null;
            }

            for (const allowed of allowedOrigins) {
                // Exact origin match (e.g. https://brainendeavor-staging.pages.dev)
                if (allowed.toLowerCase() === requestOrigin.toLowerCase()) {
                    logger.debug('CORS', `ALLOWED (Exact Match) | Origin: "${requestOrigin}" | Matched: "${allowed}"`);
                    return requestOrigin;
                }

                // Project-specific subdomain matching (e.g., hash.brainendeavor-staging.pages.dev)
                try {
                    const allowedHost = new URL(allowed.startsWith('http') ? allowed : `https://${allowed}`).hostname.toLowerCase();

                    // 1. Direct host match
                    if (reqHost === allowedHost) {
                        logger.debug('CORS', `ALLOWED (Host Match) | reqHost: "${reqHost}" | allowedHost: "${allowedHost}"`);
                        return requestOrigin;
                    }

                    // 2. Specific project subdomains (e.g., *.brainendeavor-staging.pages.dev, but NOT arbitrary other pages.dev)
                    if (reqHost.endsWith('.' + allowedHost)) {
                        logger.debug('CORS', `ALLOWED (Project Subdomain Match) | reqHost: "${reqHost}" | allowedHost: "*.${allowedHost}"`);
                        return requestOrigin;
                    }

                    // 3. Explicit wildcard pattern in allowedOrigins (e.g., *.splitphase.io)
                    if (allowedHost.startsWith('*.')) {
                        const rootDomain = allowedHost.slice(2);
                        if (reqHost === rootDomain || reqHost.endsWith('.' + rootDomain)) {
                            logger.debug('CORS', `ALLOWED (Wildcard Rule Match) | reqHost: "${reqHost}" | Rule: "${allowedHost}"`);
                            return requestOrigin;
                        }
                    }
                } catch {
                    // Ignore unparseable configured origin
                }
            }

            logger.warn(
                'CORS',
                `BLOCKED | reqHost: "${reqHost}" | Origin: "${requestOrigin}" | Allowed: [${allowedOrigins.join(', ')}]`
            );
            return null;
        },
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
        maxAge: 86400,
    });

    return corsMiddleware(c, next);
});

// Health check endpoint with safe configuration diagnostic status
app.get('/', (c) => {
    const knownPrefixes = [
        'STORAGE_ENGINE',
        'TURNSTILE_SECRET_KEY',
        'EMAIL_TO',
        'EMAIL_FROM',
        'EMAIL_PROVIDER',
        'EMAIL_API_KEY',
        'WEBHOOK_URL',
        'API_KEY',
        'RATE_LIMIT_ENABLED',
        'RATE_LIMIT_REQUESTS',
        'RATE_LIMIT_WINDOW',
        'ALLOWED_ORIGINS',
        'ENVIRONMENT',
        'LOG_LEVEL',
    ];

    const envObj = (c.env || {}) as Record<string, any>;

    const stringKeys = Object.keys(envObj).filter((key) =>
        typeof envObj[key] === 'string' &&
        knownPrefixes.some((prefix) => key === prefix || key.startsWith(`${prefix}_`))
    );

    const kvBound = !!(c.env.KV && typeof c.env.KV.get === 'function');
    const d1Bound = !!(c.env.DB && typeof c.env.DB.prepare === 'function');

    const configuredKeys = Array.from(new Set([
        ...stringKeys,
        ...(kvBound ? ['KV'] : []),
        ...(d1Bound ? ['DB'] : []),
    ]));

    const storageEngine = (c.env.STORAGE_ENGINE || (d1Bound ? 'd1' : kvBound ? 'kv' : 'none')).toLowerCase();
    const storageConfigured = storageEngine === 'd1' ? d1Bound : storageEngine === 'kv' ? kvBound : false;
    const logger = createLogger(c.env as Record<string, string | undefined>);

    return c.json({
        service: 'FreeFormer',
        version: '0.2.0',
        status: 'healthy',
        environment: c.env.ENVIRONMENT || 'production',
        logLevel: logger.getLevel(),
        config: {
            storageEngine,
            storageConfigured,
            storage: storageConfigured ? storageEngine : 'none',
            kvBound,
            d1Bound,
            emailProvider: c.env.EMAIL_PROVIDER || 'none',
            emailToConfigured: !!c.env.EMAIL_TO,
            emailFromConfigured: !!c.env.EMAIL_FROM,
            emailApiKeyConfigured: !!c.env.EMAIL_API_KEY,
            turnstileConfigured: !!c.env.TURNSTILE_SECRET_KEY,
            rateLimitEnabled: c.env.RATE_LIMIT_ENABLED === 'true',
            configuredKeys,
        },
        timestamp: new Date().toISOString(),
    });
});

// Submit form endpoint
app.post('/submit', async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);

    try {
        const clientIP = c.req.header('cf-connecting-ip') || 'unknown';

        // Rate limiting (if enabled)
        const rateLimitEnabled = c.env.RATE_LIMIT_ENABLED?.toLowerCase() === 'true';
        if (rateLimitEnabled) {
            const rateLimitResult = await checkRateLimit(
                c.env.KV,
                c.env.DB,
                clientIP,
                parseInt(c.env.RATE_LIMIT_REQUESTS || '10'),
                parseInt(c.env.RATE_LIMIT_WINDOW || '60'),
                logger
            );

            if (!rateLimitResult.allowed) {
                return c.json(
                    {
                        success: false,
                        error: 'Rate limit exceeded',
                        retryAfter: rateLimitResult.retryAfter,
                    },
                    429
                );
            }
        }

        let turnstileToken = '';
        let formId = '';
        let siteId = '';
        let data: Record<string, any> = {};

        const contentType = c.req.header('content-type') || '';

        if (contentType.includes('application/json')) {
            try {
                const body = await c.req.json();
                turnstileToken = body.turnstileToken || body['cf-turnstile-response'] || '';
                formId = body.formId || '';
                siteId = body.siteId || '';
                data = body.data || {};
            } catch {
                return c.json({ success: false, error: 'Malformed JSON payload' }, 400);
            }
        } else {
            // Parse application/x-www-form-urlencoded or multipart/form-data
            const body = await c.req.parseBody();
            turnstileToken = (body['cf-turnstile-response'] as string) || (body['turnstileToken'] as string) || '';
            formId = (body['formId'] as string) || (body['form_id'] as string) || (body['form'] as string) || 'contact';
            siteId = (body['siteId'] as string) || (body['site_id'] as string) || (body['site'] as string) || '';

            // Extract remaining form inputs as submission data
            const extractedData: Record<string, any> = {};
            const reserved = new Set([
                'cf-turnstile-response',
                'cf_turnstile_response',
                'turnstileToken',
                'turnstile_token',
                'formId',
                'form_id',
                'form',
                'siteId',
                'site_id',
                'site',
            ]);
            for (const [key, value] of Object.entries(body)) {
                if (!reserved.has(key)) {
                    extractedData[key] = value;
                }
            }
            data = extractedData;
        }

        const isDevMock =
            c.env.DEV_MOCK_TURNSTILE === 'true' ||
            c.env.DEV_MODE === 'true' ||
            c.env.ENVIRONMENT === 'development';

        // In dev mock mode, auto-fill dev token if omitted
        if (!turnstileToken && isDevMock) {
            turnstileToken = 'dev';
        }

        // Validate required fields
        if (!turnstileToken) {
            return c.json(
                { success: false, error: 'Turnstile token is required' },
                400
            );
        }

        if (!formId) {
            return c.json(
                { success: false, error: 'Form ID is required' },
                400
            );
        }

        // Resolve siteId: explicit payload -> origin/referer URL domain fallback
        let resolvedSiteId = (siteId && typeof siteId === 'string') ? siteId.trim().toLowerCase() : '';
        if (!resolvedSiteId) {
            const originOrReferer = c.req.header('origin') || c.req.header('referer');
            if (originOrReferer) {
                try {
                    resolvedSiteId = new URL(originOrReferer).hostname.replace(/^www\./i, '').toLowerCase();
                } catch {
                    // Invalid URL format, ignore
                }
            }
        }

        if (!resolvedSiteId) {
            return c.json(
                {
                    success: false,
                    error: "Site ID is required. Please provide 'siteId' in the payload, specify 'data-freeformer-site' on your form, or host on a recognized domain.",
                },
                400
            );
        }

        if (!data || typeof data !== 'object') {
            return c.json(
                { success: false, error: 'Form data is required' },
                400
            );
        }

        const envRecord = c.env as Record<string, string | undefined>;

        // Dynamic Turnstile Secret Key resolution (supports domains, underscores, and global fallbacks):
        const secretKey = resolveSiteEnv(envRecord, 'TURNSTILE_SECRET_KEY', resolvedSiteId) || '';

        // Verify Turnstile token
        const turnstileResult = await verifyTurnstile(
            turnstileToken,
            secretKey,
            clientIP,
            isDevMock,
            logger
        );

        if (!turnstileResult.success) {
            return c.json(
                {
                    success: false,
                    error: 'Turnstile verification failed',
                    details: turnstileResult.errors,
                },
                403
            );
        }

        // Prepare submission data
        const submissionData = {
            formId,
            siteId: resolvedSiteId,
            data,
            metadata: {
                ip: clientIP,
                userAgent: c.req.header('user-agent') || 'unknown',
                timestamp: new Date().toISOString(),
                turnstileScore: turnstileResult.score,
            },
        };

        // Storage Engine resolution (Global STORAGE_ENGINE -> "kv")
        const storageEngine = (c.env.STORAGE_ENGINE || 'kv').toLowerCase();

        // Store submission according to configured engine
        let submissionId = '';
        if (storageEngine === 'd1') {
            if (!c.env.DB) {
                logger.error('Storage', "STORAGE_ENGINE is set to 'd1', but D1 database binding 'DB' is missing in Wrangler!");
            }
            submissionId = await storeSubmission(submissionData, undefined, c.env.DB, logger);
        } else if (storageEngine === 'kv') {
            if (!c.env.KV) {
                logger.error('Storage', "STORAGE_ENGINE is set to 'kv', but KV namespace binding 'KV' is missing in Wrangler!");
            }
            submissionId = await storeSubmission(submissionData, c.env.KV, undefined, logger);
        } else {
            // 'none': process without persistence
            submissionId = await storeSubmission(submissionData, undefined, undefined, logger);
        }

        // Dynamic Per-Site Email & Webhook Resolution (supports domains, prefixes, and global fallbacks):
        const resolvedEmailTo = resolveSiteEnv(envRecord, 'EMAIL_TO', resolvedSiteId) || '';
        const resolvedEmailFrom = resolveSiteEnv(envRecord, 'EMAIL_FROM', resolvedSiteId) || '';
        const resolvedEmailProvider = (resolveSiteEnv(envRecord, 'EMAIL_PROVIDER', resolvedSiteId) || 'none').toLowerCase() as any;
        const resolvedEmailApiKey = resolveSiteEnv(envRecord, 'EMAIL_API_KEY', resolvedSiteId) || '';
        const resolvedMailgunDomain = resolveSiteEnv(envRecord, 'MAILGUN_DOMAIN', resolvedSiteId);
        const resolvedMailtrapInboxId = resolveSiteEnv(envRecord, 'MAILTRAP_INBOX_ID', resolvedSiteId);

        // Send email notification (if configured)
        const emailConfig: EmailConfig = {
            provider: resolvedEmailProvider,
            apiKey: resolvedEmailApiKey,
            from: resolvedEmailFrom,
            to: resolvedEmailTo,
            mailgunDomain: resolvedMailgunDomain,
            mailtrapInboxId: resolvedMailtrapInboxId,
            siteId: resolvedSiteId,
        };

        if (emailConfig.provider !== 'none') {
            if (!emailConfig.to || !emailConfig.from) {
                logger.warn('Email', `Skipped: Missing EMAIL_TO ("${emailConfig.to}") or EMAIL_FROM ("${emailConfig.from}") for siteId: "${resolvedSiteId}"`);
            } else {
                const emailPromise = sendEmailNotification(emailConfig, {
                    ...submissionData,
                    submissionId,
                }, logger)
                    .then((result) => {
                        if (result && !result.success) {
                            logger.error('Email', `Dispatch failed: ${result.error}`);
                        } else {
                            logger.info('Email', `Dispatch complete for site "${resolvedSiteId}" via ${emailConfig.provider}`);
                        }
                    })
                    .catch((error) => {
                        logger.error('Email', 'Dispatch exception', error);
                    });
                c.executionCtx.waitUntil(emailPromise);
            }
        } else {
            logger.debug('Email', `Provider resolved to "none" for siteId: "${resolvedSiteId}"`);
        }

        // Send webhook (if configured)
        const webhookUrl = resolveSiteEnv(envRecord, 'WEBHOOK_URL', resolvedSiteId);

        if (webhookUrl) {
            const webhookPromise = fetch(webhookUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-FreeFormer-Event': 'submission',
                    'X-FreeFormer-Signature': c.env.API_KEY || '' // Simple auth if key exists
                },
                body: JSON.stringify({
                    id: submissionId,
                    ...submissionData,
                    timestamp: new Date().toISOString()
                })
            }).then(res => {
                if (!res.ok) logger.error('Webhook', `Webhook failed with status: ${res.status} ${res.statusText}`);
            }).catch(err => {
                logger.error('Webhook', 'Webhook dispatch exception', err);
            });

            c.executionCtx.waitUntil(webhookPromise);
        }

        logger.info('Submit', `Processed submission ${submissionId} for site "${resolvedSiteId}"`);

        return c.json({
            success: true,
            submissionId,
            message: 'Form submitted successfully',
        });
    } catch (error) {
        logger.error('Submit', 'Unhandled error processing form submission', error);
        return c.json(
            {
                success: false,
                error: 'Internal server error',
            },
            500
        );
    }
});

// Get all submissions for a form (requires authentication)
app.get('/submissions/:formId', async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);

    try {
        // Authentication
        const apiKey = c.env.API_KEY;
        if (!apiKey) {
            return c.json({ success: false, error: 'API key not configured' }, 500);
        }

        const authHeader = c.req.header('authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ') || authHeader.split(' ')[1] !== apiKey) {
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        const formId = c.req.param('formId');
        const siteId = c.req.query('siteId');

        if (!siteId || !siteId.trim()) {
            return c.json(
                {
                    success: false,
                    error: "Missing required 'siteId' query parameter (e.g. /submissions/:formId?siteId=mysite)",
                },
                400
            );
        }

        const cleanSite = siteId.trim().toLowerCase();
        const limit = parseInt(c.req.query('limit') || '100');
        const offset = parseInt(c.req.query('offset') || '0');

        // Storage Engine resolution (Global STORAGE_ENGINE -> "kv")
        const storageEngine = (c.env.STORAGE_ENGINE || 'kv').toLowerCase();

        const submissions = await getSubmissions(
            storageEngine === 'kv' ? c.env.KV : undefined,
            storageEngine === 'd1' ? c.env.DB : undefined,
            formId,
            cleanSite,
            limit,
            offset
        );

        return c.json({
            success: true,
            formId,
            siteId: cleanSite,
            storageEngine,
            submissions,
            pagination: {
                limit,
                offset,
            },
        });
    } catch (error) {
        logger.error('API', 'Error fetching submissions', error);
        return c.json(
            {
                success: false,
                error: 'Internal server error',
            },
            500
        );
    }
});

// Get a specific submission (requires authentication)
app.get('/submission/:id', async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);

    try {
        // Authentication
        const apiKey = c.env.API_KEY;
        if (!apiKey) {
            return c.json({ success: false, error: 'API key not configured' }, 500);
        }

        const authHeader = c.req.header('authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ') || authHeader.split(' ')[1] !== apiKey) {
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        const submissionId = c.req.param('id');
        const siteId = c.req.query('siteId');
        const formId = c.req.query('formId');

        // Storage Engine resolution (Global STORAGE_ENGINE -> "kv")
        const storageEngine = (c.env.STORAGE_ENGINE || 'kv').toLowerCase();

        const submission = await getSubmission(
            storageEngine === 'kv' ? c.env.KV : undefined,
            storageEngine === 'd1' ? c.env.DB : undefined,
            submissionId,
            siteId,
            formId
        );

        if (!submission) {
            return c.json(
                { success: false, error: 'Submission not found' },
                404
            );
        }

        return c.json({
            success: true,
            submission,
        });
    } catch (error) {
        logger.error('API', 'Error fetching submission', error);
        return c.json(
            {
                success: false,
                error: 'Internal server error',
            },
            500
        );
    }
});

// Test email configuration (requires authentication)
app.post('/email-test', async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);

    try {
        // Authentication
        const apiKey = c.env.API_KEY;
        if (!apiKey) {
            return c.json({ success: false, error: 'API key not configured' }, 500);
        }

        const authHeader = c.req.header('authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ') || authHeader.split(' ')[1] !== apiKey) {
            return c.json({ success: false, error: 'Unauthorized' }, 401);
        }

        // Create dummy submission data
        const submissionData = {
            formId: 'test-email-form',
            submissionId: 'test-' + Date.now(),
            data: {
                message: 'This is a test email from FreeFormer.',
                timestamp: new Date().toISOString(),
                test: true
            },
            metadata: {
                ip: c.req.header('cf-connecting-ip') || 'unknown',
                userAgent: c.req.header('user-agent') || 'unknown',
                timestamp: new Date().toISOString(),
            },
        };

        // Configure email
        const emailConfig: EmailConfig = {
            provider: (c.env.EMAIL_PROVIDER?.toLowerCase() as any) || 'none',
            apiKey: c.env.EMAIL_API_KEY || '',
            from: c.env.EMAIL_FROM || '',
            to: c.env.EMAIL_TO || '',
            mailgunDomain: c.env.MAILGUN_DOMAIN,
            mailtrapInboxId: c.env.MAILTRAP_INBOX_ID,
        };

        // Send email
        const result = await sendEmailNotification(emailConfig, submissionData, logger);

        if (result.success) {
            return c.json({
                success: true,
                message: 'Test email sent successfully',
                provider: emailConfig.provider
            });
        } else {
            return c.json({
                success: false,
                error: 'Failed to send test email',
                details: result.error
            }, 500);
        }

    } catch (error) {
        logger.error('API', 'Error sending test email', error);
        return c.json(
            {
                success: false,
                error: 'Internal server error',
                details: error instanceof Error ? error.message : String(error)
            },
            500
        );
    }
});

export default app;

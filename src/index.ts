import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyTurnstile } from './turnstile';
import { storeSubmission, getSubmissions, getSubmission, updateSubmissionMetadata } from './storage';
import { checkRateLimit } from './ratelimit';
import { sendEmailNotification, type EmailConfig } from './email';
import { createLogger, type Logger } from './logger';
import { requireZeroTrustAuth } from './auth';
import {
    saveAttachmentToR2,
    validateAttachment,
    verifySignedDownloadToken,
    getSandboxedFileHeaders,
    type StoredAttachment,
} from './files';
import { buildWebhookPayload, dispatchWebhook } from './webhook';
import { adminApp } from './admin';
import { evaluateSpam } from './spam/detector';
import { generateAndSendSpamDigest } from './spam/digest';
import { type SpamAnalysisResult } from './spam/types';
import { evaluateWithSys1Pop, probeSys1Pop } from './spam/sys1pop';

type Bindings = {
    KV?: KVNamespace;
    DB?: D1Database;
    ATTACHMENTS?: R2Bucket;
    SYS1POP?: Fetcher | string;
    SYS1POP_MODEL?: string;
    SYS1POP_API_TOKEN?: string;
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
    SPAM_DETECTION_ENABLED?: string;
    SPAM_THRESHOLD?: string;
    SPAM_CATEGORIES?: string;
    SPAM_HONEYPOT_FIELDS?: string;
    SPAM_KEYWORDS?: string;
    SPAM_DIGEST_ENABLED?: string;
    SPAM_DIGEST_SCHEDULE?: string;
    SPAM_DIGEST_MODE?: string;
    SPAM_DIGEST_EMAIL_TO?: string;
    EMAIL_PROVIDER?: string;
    EMAIL_API_KEY?: string;
    EMAIL_FROM?: string;
    EMAIL_TO?: string;
    MAILGUN_DOMAIN?: string;
    MAILTRAP_INBOX_ID?: string;
    ZOHO_API_URL?: string;
    API_KEY?: string;
    WEBHOOK_URL?: string;
    WEBHOOK_SECRET?: string;
    PROTECTED_FIELDS?: string;
    CF_ACCESS_ENABLED?: string;
    CF_ACCESS_TEAM_DOMAIN?: string;
    CF_ACCESS_AUD?: string;
    SIGNED_URL_TTL_SECONDS?: string;
    MAX_FILE_SIZE_MB?: string;
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

export function resolveSiteId(originOrReferer?: string, explicitSiteId?: string): string {
    if (explicitSiteId && typeof explicitSiteId === 'string' && explicitSiteId.trim()) {
        return explicitSiteId.trim().toLowerCase();
    }
    if (originOrReferer) {
        try {
            return new URL(originOrReferer).hostname.replace(/^www\./i, '').toLowerCase();
        } catch {
            // Invalid URL format, fallback to default
        }
    }
    return 'default';
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
app.get('/', async (c) => {
    const knownPrefixes = [
        'STORAGE_ENGINE',
        'TURNSTILE_SECRET_KEY',
        'EMAIL_TO',
        'EMAIL_FROM',
        'EMAIL_PROVIDER',
        'EMAIL_API_KEY',
        'ZOHO_API_URL',
        'WEBHOOK_URL',
        'WEBHOOK_SECRET',
        'PROTECTED_FIELDS',
        'CF_ACCESS',
        'API_KEY',
        'RATE_LIMIT_ENABLED',
        'RATE_LIMIT_REQUESTS',
        'RATE_LIMIT_WINDOW',
        'ALLOWED_ORIGINS',
        'ENVIRONMENT',
        'LOG_LEVEL',
        'MAX_FILE_SIZE_MB',
        'SIGNED_URL_TTL_SECONDS',
        'SPAM_DETECTION_ENABLED',
        'SPAM_THRESHOLD',
        'SPAM_HONEYPOT_FIELDS',
        'SPAM_KEYWORDS',
        'SPAM_DIGEST_ENABLED',
        'SPAM_DIGEST_SCHEDULE',
        'SPAM_DIGEST_EMAIL_TO',
        'SYS1POP',
        'SYS1POP_MODEL',
        'SYS1POP_API_TOKEN',
    ];

    const envObj = (c.env || {}) as Record<string, any>;

    const stringKeys = Object.keys(envObj).filter((key) =>
        typeof envObj[key] === 'string' &&
        knownPrefixes.some((prefix) => key === prefix || key.startsWith(`${prefix}_`))
    );

    const kvBound = !!(c.env.KV && typeof c.env.KV.get === 'function');
    const d1Bound = !!(c.env.DB && typeof c.env.DB.prepare === 'function');
    const r2Bound = !!(c.env.ATTACHMENTS && typeof c.env.ATTACHMENTS.get === 'function');
    const sys1popBound = !!(c.env.SYS1POP && (typeof c.env.SYS1POP === 'string' || typeof (c.env.SYS1POP as any).fetch === 'function'));

    const configuredKeys = Array.from(new Set([
        ...stringKeys,
        ...(kvBound ? ['KV'] : []),
        ...(d1Bound ? ['DB'] : []),
        ...(r2Bound ? ['ATTACHMENTS'] : []),
        ...(sys1popBound ? ['SYS1POP'] : []),
    ]));

    const storageEngine = (c.env.STORAGE_ENGINE || (d1Bound ? 'd1' : kvBound ? 'kv' : 'none')).toLowerCase();
    const storageConfigured = storageEngine === 'd1' ? d1Bound : storageEngine === 'kv' ? kvBound : false;
    const logger = createLogger(c.env as Record<string, string | undefined>);

    let sys1popProbe;
    if (c.req.query('probe') === 'sys1pop' || c.req.query('probe') === 'all') {
        const probeSiteId = resolveSiteId(c.req.header('origin') || c.req.header('referer'), c.req.query('siteId'));
        const sys1Target = resolveSiteEnv(envObj, 'SYS1POP', probeSiteId) || c.env.SYS1POP;
        const sys1Model = resolveSiteEnv(envObj, 'SYS1POP_MODEL', probeSiteId) || 'spam-detector-v1';
        const sys1Token = resolveSiteEnv(envObj, 'SYS1POP_API_TOKEN', probeSiteId);
        sys1popProbe = await probeSys1Pop(sys1Target, probeSiteId, sys1Model, sys1Token);
    }

    return c.json({
        service: 'FreeFormer',
        version: '0.4.0',
        status: 'healthy',
        environment: c.env.ENVIRONMENT || 'production',
        logLevel: logger.getLevel(),
        config: {
            storageEngine,
            storageConfigured,
            storage: storageConfigured ? storageEngine : 'none',
            kvBound,
            d1Bound,
            attachmentsBound: r2Bound,
            zeroTrustConfigured: !!(c.env.CF_ACCESS_TEAM_DOMAIN || c.env.CF_ACCESS_ENABLED === 'true'),
            emailProvider: c.env.EMAIL_PROVIDER || 'none',
            emailToConfigured: !!c.env.EMAIL_TO,
            emailFromConfigured: !!c.env.EMAIL_FROM,
            emailApiKeyConfigured: !!c.env.EMAIL_API_KEY,
            turnstileConfigured: !!c.env.TURNSTILE_SECRET_KEY,
            webhookConfigured: !!c.env.WEBHOOK_URL,
            rateLimitEnabled: c.env.RATE_LIMIT_ENABLED === 'true',
            spamDetectionEnabled: c.env.SPAM_DETECTION_ENABLED !== 'false',
            spamThreshold: parseInt(c.env.SPAM_THRESHOLD || '60', 10),
            spamDigestEnabled: c.env.SPAM_DIGEST_ENABLED !== 'false',
            sys1popConfigured: !!(c.env.SYS1POP || Object.keys(c.env).some(k => k === 'SYS1POP' || k.startsWith('SYS1POP_'))),
            sys1popModel: c.env.SYS1POP_MODEL || 'spam-detector-v1',
            sys1popTokenConfigured: !!(c.env.SYS1POP_API_TOKEN || Object.keys(c.env).some(k => k.startsWith('SYS1POP_API_TOKEN_'))),
            configuredKeys,
        },
        ...(sys1popProbe ? { sys1popProbe } : {}),
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
        const clientProtectedFields: string[] = [];
        const uploadedFiles: File[] = [];

        const contentType = c.req.header('content-type') || '';

        if (contentType.includes('application/json')) {
            try {
                const body = await c.req.json();
                turnstileToken = body.turnstileToken || body['cf-turnstile-response'] || '';
                formId = body.formId || '';
                siteId = body.siteId || '';
                data = body.data || {};

                if (body.options?.protectedFields && Array.isArray(body.options.protectedFields)) {
                    clientProtectedFields.push(...body.options.protectedFields);
                } else if (body.protectedFields && Array.isArray(body.protectedFields)) {
                    clientProtectedFields.push(...body.protectedFields);
                }
            } catch {
                return c.json({ success: false, error: 'Malformed JSON payload' }, 400);
            }
        } else {
            // Parse application/x-www-form-urlencoded or multipart/form-data
            const body = await c.req.parseBody({ all: true });
            turnstileToken = (body['cf-turnstile-response'] as string) || (body['turnstileToken'] as string) || '';
            formId = (body['formId'] as string) || (body['form_id'] as string) || (body['form'] as string) || 'contact';
            siteId = (body['siteId'] as string) || (body['site_id'] as string) || (body['site'] as string) || '';

            // Extract remaining form inputs as submission data or files
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
                '_protectedFields',
                'protectedFields',
            ]);

            for (const [key, value] of Object.entries(body)) {
                if (reserved.has(key)) {
                    if ((key === '_protectedFields' || key === 'protectedFields') && typeof value === 'string') {
                        const parsed = value.split(',').map((s) => s.trim()).filter(Boolean);
                        clientProtectedFields.push(...parsed);
                    }
                    continue;
                }

                // Handle file attachments
                if (Array.isArray(value)) {
                    for (const item of value) {
                        if (typeof File !== 'undefined' && item instanceof File) {
                            if (item.size > 0) uploadedFiles.push(item);
                        } else {
                            if (!extractedData[key]) extractedData[key] = [];
                            extractedData[key].push(item);
                        }
                    }
                } else if (typeof File !== 'undefined' && value instanceof File) {
                    if (value.size > 0) uploadedFiles.push(value);
                } else {
                    extractedData[key] = value;
                }
            }
            data = extractedData;
        }

        // Header protected fields
        const headerProtected = c.req.header('x-freeformer-protected-fields') || c.req.header('x-protected-fields');
        if (headerProtected) {
            const parsed = headerProtected.split(',').map((s) => s.trim()).filter(Boolean);
            clientProtectedFields.push(...parsed);
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

        if (turnstileToken === 'dev' && !isDevMock) {
            logger.warn('Turnstile', 'Rejected "dev" token in production environment');
            return c.json(
                {
                    success: false,
                    error: 'Turnstile verification failed',
                    details: ['invalid-input-response'],
                },
                403
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

        // Pre-generate submissionId for R2 key namespacing
        const submissionId = crypto.randomUUID();

        // Validate and save file attachments (R2 Storage)
        const maxFileSizeBytes = parseInt(c.env.MAX_FILE_SIZE_MB || '10', 10) * 1024 * 1024;
        const storedAttachments: StoredAttachment[] = [];

        if (uploadedFiles.length > 0) {
            for (const file of uploadedFiles) {
                const validation = validateAttachment(file, maxFileSizeBytes);
                if (!validation.valid) {
                    return c.json({ success: false, error: validation.error }, 400);
                }
            }

            if (c.env.ATTACHMENTS) {
                for (const file of uploadedFiles) {
                    const stored = await saveAttachmentToR2(
                        c.env.ATTACHMENTS,
                        file,
                        resolvedSiteId,
                        formId,
                        submissionId,
                        logger
                    );
                    storedAttachments.push(stored);
                }
            } else {
                logger.warn('Storage', 'Files uploaded but ATTACHMENTS R2 binding is not configured in Wrangler!');
            }
        }

        // Resolve protected fields (combining client declaration and server env)
        const envProtectedRaw = resolveSiteEnv(envRecord, 'PROTECTED_FIELDS', resolvedSiteId) ||
            resolveSiteEnv(envRecord, 'EMAIL_PROTECTED_FIELDS', resolvedSiteId) ||
            resolveSiteEnv(envRecord, 'SENSITIVE_FIELDS', resolvedSiteId) || '';
        const envProtectedList = envProtectedRaw.split(',').map((s) => s.trim()).filter(Boolean);
        const resolvedProtectedFields = Array.from(new Set([...clientProtectedFields, ...envProtectedList]));

        // Evaluate submission for spam (Honeypot, Velocity, Link Density, Keywords, Disposable Email)
        const spamEnabled = resolveSiteEnv(envRecord, 'SPAM_DETECTION_ENABLED', resolvedSiteId) !== 'false' &&
            c.env.SPAM_DETECTION_ENABLED !== 'false';

        let spamAnalysis: SpamAnalysisResult | undefined;
        let isSpam = false;

        if (spamEnabled) {
            const spamThresholdRaw = resolveSiteEnv(envRecord, 'SPAM_THRESHOLD', resolvedSiteId) || c.env.SPAM_THRESHOLD || '60';
            const spamThreshold = parseInt(spamThresholdRaw, 10) || 60;

            const spamCategoriesRaw = resolveSiteEnv(envRecord, 'SPAM_CATEGORIES', resolvedSiteId) ||
                c.env.SPAM_CATEGORIES ||
                'all';

            const honeypotFieldsRaw = resolveSiteEnv(envRecord, 'SPAM_HONEYPOT_FIELDS', resolvedSiteId) ||
                c.env.SPAM_HONEYPOT_FIELDS || '';
            const customHoneypots = honeypotFieldsRaw
                ? honeypotFieldsRaw.split(',').map((s) => s.trim()).filter(Boolean)
                : undefined;

            const customKeywordsRaw = resolveSiteEnv(envRecord, 'SPAM_KEYWORDS', resolvedSiteId) ||
                c.env.SPAM_KEYWORDS || '';
            const customKeywords = customKeywordsRaw
                ? customKeywordsRaw.split(',').map((s) => s.trim()).filter(Boolean)
                : undefined;

            spamAnalysis = evaluateSpam(data, {
                threshold: spamThreshold,
                categories: spamCategoriesRaw,
                honeypotFields: customHoneypots,
                customKeywords,
                clientIp: clientIP,
                turnstileResult,
                requestTimestamp: Date.now(),
            });

            isSpam = spamAnalysis.isSpam;
        }

        // Prepare submission data
        const submissionData = {
            formId,
            siteId: resolvedSiteId,
            data,
            attachments: storedAttachments,
            protectedFields: resolvedProtectedFields,
            metadata: {
                ip: clientIP,
                userAgent: c.req.header('user-agent') || 'unknown',
                timestamp: new Date().toISOString(),
                turnstileScore: turnstileResult.score,
                isSpam,
                spamScore: spamAnalysis?.score,
                spam: spamAnalysis,
            },
        };

        // Storage Engine resolution (Global STORAGE_ENGINE -> "kv")
        const storageEngine = (c.env.STORAGE_ENGINE || 'kv').toLowerCase();

        // Store submission according to configured engine
        if (storageEngine === 'd1') {
            if (!c.env.DB) {
                logger.error('Storage', "STORAGE_ENGINE is set to 'd1', but D1 database binding 'DB' is missing in Wrangler!");
            }
            await storeSubmission({ ...submissionData, id: submissionId }, undefined, c.env.DB, logger);
        } else if (storageEngine === 'kv') {
            if (!c.env.KV) {
                logger.error('Storage', "STORAGE_ENGINE is set to 'kv', but KV namespace binding 'KV' is missing in Wrangler!");
            }
            await storeSubmission({ ...submissionData, id: submissionId }, c.env.KV, undefined, logger);
        } else {
            // 'none': process without persistence
            await storeSubmission({ ...submissionData, id: submissionId }, undefined, undefined, logger);
        }

        // Dynamic Per-Site Email & Webhook Resolution (supports domains, prefixes, and global fallbacks):
        const resolvedEmailTo = resolveSiteEnv(envRecord, 'EMAIL_TO', resolvedSiteId) || '';
        const resolvedEmailFrom = resolveSiteEnv(envRecord, 'EMAIL_FROM', resolvedSiteId) || '';
        const resolvedEmailProvider = (resolveSiteEnv(envRecord, 'EMAIL_PROVIDER', resolvedSiteId) || 'none').toLowerCase() as any;
        const resolvedEmailApiKey = resolveSiteEnv(envRecord, 'EMAIL_API_KEY', resolvedSiteId) || '';
        const resolvedMailgunDomain = resolveSiteEnv(envRecord, 'MAILGUN_DOMAIN', resolvedSiteId);
        const resolvedMailtrapInboxId = resolveSiteEnv(envRecord, 'MAILTRAP_INBOX_ID', resolvedSiteId);
        const resolvedZohoApiUrl = resolveSiteEnv(envRecord, 'ZOHO_API_URL', resolvedSiteId);

        // Configure outbound email
        const emailConfig: EmailConfig = {
            provider: resolvedEmailProvider,
            apiKey: resolvedEmailApiKey,
            from: resolvedEmailFrom,
            to: resolvedEmailTo,
            mailgunDomain: resolvedMailgunDomain,
            mailtrapInboxId: resolvedMailtrapInboxId,
            zohoApiUrl: resolvedZohoApiUrl,
            siteId: resolvedSiteId,
            protectedFields: resolvedProtectedFields,
        };

        const webhookUrl = resolveSiteEnv(envRecord, 'WEBHOOK_URL', resolvedSiteId);
        const webhookSecret = resolveSiteEnv(envRecord, 'WEBHOOK_SECRET', resolvedSiteId) || c.env.API_KEY || '';
        const signedUrlTtl = parseInt(c.env.SIGNED_URL_TTL_SECONDS || '900', 10);
        const workerOrigin = new URL(c.req.url).origin;

        // Decoupled Background Task: Asynchronous neural triage (Sys1Pop) & event dispatching
        const backgroundTask = async () => {
            let currentIsSpam = isSpam;
            let currentSpamAnalysis = spamAnalysis;
            const spamThreshold = spamAnalysis?.threshold || 60;

            // Optional Progressive Enhancement: If Sys1Pop is configured, evaluate ambiguous submissions in background
            const sys1Target = resolveSiteEnv(envRecord, 'SYS1POP', resolvedSiteId) || c.env.SYS1POP;
            if (sys1Target && !currentIsSpam && currentSpamAnalysis && currentSpamAnalysis.score >= 30) {
                try {
                    const sys1Model = resolveSiteEnv(envRecord, 'SYS1POP_MODEL', resolvedSiteId) || 'spam-detector-v1';
                    const sys1Token = resolveSiteEnv(envRecord, 'SYS1POP_API_TOKEN', resolvedSiteId);
                    const sys1Verdict = await evaluateWithSys1Pop(sys1Target, data, resolvedSiteId, sys1Model, sys1Token);
                    if (sys1Verdict?.isSpam) {
                        currentIsSpam = true;
                        currentSpamAnalysis.isSpam = true;
                        currentSpamAnalysis.score = Math.max(currentSpamAnalysis.score, spamThreshold);
                        currentSpamAnalysis.reasons.push(
                            `SYS1POP_NEURAL_SPAM: Classified as "${sys1Verdict.category}" with risk score ${sys1Verdict.riskScore}`
                        );

                        // Update stored submission metadata asynchronously
                        await updateSubmissionMetadata(
                            submissionId,
                            resolvedSiteId,
                            formId,
                            (prev) => ({
                                ...prev,
                                isSpam: true,
                                spamScore: currentSpamAnalysis?.score,
                                spam: currentSpamAnalysis,
                                sys1popVerdict: sys1Verdict,
                            }),
                            c.env.KV,
                            c.env.DB,
                            logger
                        );
                    }
                } catch (err) {
                    logger.error('Sys1Pop', 'Error during asynchronous Sys1Pop evaluation', err);
                }
            }

            if (currentIsSpam) {
                logger.warn(
                    'Spam',
                    `QUARANTINED | Site: "${resolvedSiteId}" | Score: ${currentSpamAnalysis?.score}/${currentSpamAnalysis?.threshold} | Reasons: [${currentSpamAnalysis?.reasons.join('; ')}]`
                );
                logger.info('Email', `Suppressed: Submission ${submissionId} quarantined as spam (Score: ${currentSpamAnalysis?.score}/${currentSpamAnalysis?.threshold})`);
            } else {
                logger.debug(
                    'Spam',
                    `PASSED | Site: "${resolvedSiteId}" | Score: ${currentSpamAnalysis?.score}/${currentSpamAnalysis?.threshold}`
                );

                // Send email notification (if configured and clean)
                if (emailConfig.provider !== 'none') {
                    if (!emailConfig.to || !emailConfig.from) {
                        logger.warn('Email', `Skipped: Missing EMAIL_TO ("${emailConfig.to}") or EMAIL_FROM ("${emailConfig.from}") for siteId: "${resolvedSiteId}"`);
                    } else {
                        try {
                            const emailResult = await sendEmailNotification(emailConfig, {
                                ...submissionData,
                                submissionId,
                            }, logger);
                            if (emailResult && !emailResult.success) {
                                logger.error('Email', `Dispatch failed: ${emailResult.error}`);
                            } else {
                                logger.info('Email', `Dispatch complete for site "${resolvedSiteId}" via ${emailConfig.provider}`);
                            }
                        } catch (error) {
                            logger.error('Email', 'Dispatch exception', error);
                        }
                    }
                }

                // Send universal webhook (if configured)
                if (webhookUrl) {
                    try {
                        const payload = await buildWebhookPayload(
                            { ...submissionData, submissionId },
                            workerOrigin,
                            webhookSecret,
                            signedUrlTtl
                        );
                        await dispatchWebhook(webhookUrl, payload, webhookSecret, logger);
                    } catch (err) {
                        logger.error('Webhook', 'Webhook dispatch exception', err);
                    }
                }
            }
        };

        if (c.executionCtx?.waitUntil) {
            c.executionCtx.waitUntil(backgroundTask());
        } else {
            await backgroundTask();
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
            zohoApiUrl: c.env.ZOHO_API_URL,
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

// Test Sys1Pop neural edge decision engine connection & model triage
app.all('/sys1pop-test', async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);
    try {
        const querySiteId = c.req.query('siteId');
        const headerOrigin = c.req.header('origin') || c.req.header('referer');
        const resolvedSiteId = resolveSiteId(headerOrigin, querySiteId);

        const envRecord = c.env as Record<string, string | undefined>;
        const sys1Model = resolveSiteEnv(envRecord, 'SYS1POP_MODEL', resolvedSiteId) || 'spam-detector-v1';
        const sys1Token = resolveSiteEnv(envRecord, 'SYS1POP_API_TOKEN', resolvedSiteId);

        const sys1Target = resolveSiteEnv(envRecord, 'SYS1POP', resolvedSiteId) || c.env.SYS1POP;
        const probe = await probeSys1Pop(sys1Target, resolvedSiteId, sys1Model, sys1Token);

        const statusCode = probe.success ? 200 : probe.configured ? 502 : 404;
        return c.json({
            service: 'FreeFormer',
            target: 'Sys1Pop',
            siteId: resolvedSiteId,
            ...probe,
        }, statusCode as any);
    } catch (error) {
        logger.error('API', 'Error testing Sys1Pop connection', error);
        return c.json({
            service: 'FreeFormer',
            target: 'Sys1Pop',
            success: false,
            error: 'Internal server error during Sys1Pop probe',
            details: error instanceof Error ? error.message : String(error)
        }, 500);
    }
});

// Test Turnstile configuration & perform live Cloudflare siteverify ping
app.post('/turnstile-test', requireZeroTrustAuth(), async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);
    try {
        const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
        const siteId = (body.siteId as string) || c.req.query('siteId') || 'brainendeavor';
        const envRecord = c.env as Record<string, string | undefined>;
        const secretKey = resolveSiteEnv(envRecord, 'TURNSTILE_SECRET_KEY', siteId) || '';

        if (!secretKey) {
            return c.json(
                {
                    success: false,
                    error: `No Turnstile secret key resolved for site "${siteId}"`,
                    hint: `Set TURNSTILE_SECRET_KEY_${siteId.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()} via wrangler secret put`,
                },
                400
            );
        }

        // Test token: use provided token or Cloudflare official dummy token
        const testToken = (body.turnstileToken as string) || '1x00000000000000000000AA';
        const clientIP = c.req.header('cf-connecting-ip') || '';

        const formData = new FormData();
        formData.append('secret', secretKey);
        formData.append('response', testToken);
        if (clientIP && clientIP !== 'unknown') {
            formData.append('remoteip', clientIP);
        }

        const cfRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData,
        });

        const cfResult = (await cfRes.json()) as {
            success: boolean;
            score?: number;
            'error-codes'?: string[];
            challenge_ts?: string;
            hostname?: string;
        };

        const keyPrefix = secretKey.length > 10 ? secretKey.substring(0, 10) + '...' : '***';

        // Cloudflare returns invalid-input-response when secret key is valid but token is dummy/expired
        const secretKeyValid = cfResult.success || !cfResult['error-codes']?.includes('invalid-input-secret');

        logger.info('Turnstile', `Diagnostic test for site "${siteId}" - secret key valid: ${secretKeyValid}, cf success: ${cfResult.success}`);

        return c.json({
            success: secretKeyValid,
            siteId,
            secretKeyConfigured: true,
            secretKeyPrefix: keyPrefix,
            cloudflareResponse: cfResult,
            message: secretKeyValid
                ? 'Cloudflare Turnstile siteverify reached and secret key verified successfully'
                : 'Cloudflare Turnstile rejected secret key (invalid-input-secret)',
        });
    } catch (error) {
        logger.error('API', 'Error testing Turnstile verification', error);
        return c.json(
            {
                success: false,
                error: 'Internal server error during Turnstile test',
                details: error instanceof Error ? error.message : String(error),
            },
            500
        );
    }
});

// Test webhook configuration (requires authentication)
app.post('/webhook-test', requireZeroTrustAuth(), async (c) => {
    const logger = createLogger(c.env as Record<string, string | undefined>);
    try {
        const body = (await c.req.json().catch(() => ({}))) as Record<string, any>;
        const siteId = (body.siteId as string) || 'splitphase.io';
        const formId = (body.formId as string) || 'contact';
        const envRecord = c.env as Record<string, string | undefined>;
        const webhookUrl = (body.webhookUrl as string) || resolveSiteEnv(envRecord, 'WEBHOOK_URL', siteId);
        const webhookSecret = resolveSiteEnv(envRecord, 'WEBHOOK_SECRET', siteId) || c.env.API_KEY || '';

        if (!webhookUrl) {
            return c.json(
                { success: false, error: 'No webhookUrl provided in payload or configured in WEBHOOK_URL environment variable' },
                400
            );
        }

        const workerOrigin = new URL(c.req.url).origin;
        const testPayload = await buildWebhookPayload(
            {
                submissionId: 'test-' + Date.now(),
                formId,
                siteId,
                data: body.data || {
                    name: 'Alex Johnson',
                    email: 'alex@example.com',
                    company: 'Acme Corp',
                    message: 'This is a test submission from FreeFormer to verify webhook integration.',
                },
                metadata: {
                    ip: c.req.header('cf-connecting-ip') || '127.0.0.1',
                    userAgent: c.req.header('user-agent') || 'FreeFormer-Webhook-Test',
                    timestamp: new Date().toISOString(),
                    turnstileScore: 1.0,
                },
            },
            workerOrigin,
            webhookSecret,
            900
        );
        testPayload.event = 'test_submission';

        const result = await dispatchWebhook(webhookUrl, testPayload, webhookSecret, logger);

        return c.json(
            {
                success: result.success,
                webhookUrl,
                status: result.status,
                error: result.error,
                payload: testPayload,
            },
            result.success ? 200 : 502
        );
    } catch (error) {
        logger.error('Webhook', 'Exception testing webhook', error);
        return c.json(
            {
                success: false,
                error: 'Internal server error',
                details: error instanceof Error ? error.message : String(error),
            },
            500
        );
    }
});

// Signed file download endpoint (time-limited HMAC for automated webhooks / Zapier)
app.get('/files/signed', async (c) => {
    const key = c.req.query('key');
    const expires = c.req.query('expires');
    const token = c.req.query('token');
    const secret = c.env.WEBHOOK_SECRET || c.env.API_KEY;

    if (!key || !expires || !token || !secret) {
        return c.json({ success: false, error: 'Invalid or missing signed download parameters' }, 400);
    }

    const isValid = await verifySignedDownloadToken(key, expires, token, secret);
    if (!isValid) {
        return c.json({ success: false, error: 'Invalid or expired download token' }, 403);
    }

    if (!c.env.ATTACHMENTS) {
        return c.json({ success: false, error: 'ATTACHMENTS R2 bucket binding is not configured in Wrangler' }, 500);
    }

    const object = await c.env.ATTACHMENTS.get(key);
    if (!object) {
        return c.json({ success: false, error: 'File not found' }, 404);
    }

    const filename = key.split('/').pop() || 'file';
    const mimeType = object.httpMetadata?.contentType || 'application/octet-stream';
    return new Response(object.body, {
        headers: getSandboxedFileHeaders(filename, mimeType),
    });
});

// Zero-Trust protected file download/preview endpoint
app.get('/files/:key{.*}', requireZeroTrustAuth(), async (c) => {
    const key = c.req.param('key');
    if (!key) {
        return c.json({ success: false, error: 'File key is required' }, 400);
    }

    if (!c.env.ATTACHMENTS) {
        return c.json({ success: false, error: 'ATTACHMENTS R2 bucket binding is not configured in Wrangler' }, 500);
    }

    const object = await c.env.ATTACHMENTS.get(key);
    if (!object) {
        return c.json({ success: false, error: 'File not found' }, 404);
    }

    const filename = key.split('/').pop() || 'file';
    const mimeType = object.httpMetadata?.contentType || 'application/octet-stream';
    return new Response(object.body, {
        headers: getSandboxedFileHeaders(filename, mimeType),
    });
});

// Mount Zero-Trust Admin UI
app.use('/admin/*', requireZeroTrustAuth());
app.use('/admin', requireZeroTrustAuth());
app.route('/admin', adminApp);

// Export app for tests and router mounting
export { app };

// Cloudflare Workers entrypoint supporting HTTP fetch and Scheduled Events (crons)
export default {
    fetch: app.fetch,
    async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) {
        const logger = createLogger(env as Record<string, string | undefined>);
        logger.info('Cron', `Scheduled cron triggered: "${event.cron}" at ${new Date().toISOString()}`);

        if (env.SPAM_DIGEST_ENABLED === 'false') {
            logger.info('Cron', 'Spam digest is disabled via SPAM_DIGEST_ENABLED=false');
            return;
        }

        const emailConfig: EmailConfig = {
            provider: ((env.EMAIL_PROVIDER || 'none').toLowerCase()) as any,
            apiKey: env.EMAIL_API_KEY || '',
            from: env.EMAIL_FROM || '',
            to: env.SPAM_DIGEST_EMAIL_TO || env.EMAIL_TO || '',
            mailgunDomain: env.MAILGUN_DOMAIN,
            mailtrapInboxId: env.MAILTRAP_INBOX_ID,
            zohoApiUrl: env.ZOHO_API_URL,
        };

        const result = await generateAndSendSpamDigest(
            { kv: env.KV, db: env.DB },
            emailConfig,
            { days: 7, mode: (env.SPAM_DIGEST_MODE as any) || 'comprehensive' },
            logger
        );

        logger.info(
            'Cron',
            `Spam digest execution completed: sent=${result.sent}, count=${result.count}, reason=${result.reason || 'ok'}`
        );
    },
};


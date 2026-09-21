import { type Logger } from './logger';

/**
 * Verify Cloudflare Turnstile token
 */
export async function verifyTurnstile(
    token: string,
    secretKey: string,
    remoteIP: string,
    isDevMock: boolean = false,
    logger?: Logger
): Promise<{
    success: boolean;
    score?: number;
    errors?: string[];
}> {
    // Explicit Dev Mode or Cloudflare official dummy test keys
    if (
        isDevMock ||
        (token === '1x00000000000000000000AA' && secretKey === '1x00000000000000000000AA00000000000')
    ) {
        if (logger) {
            logger.debug('Turnstile', '⚡ Dev Mock Verification Auto-Passed');
        } else {
            console.log('⚡ [FreeFormer Turnstile] Dev Mock Verification Auto-Passed');
        }
        return {
            success: true,
            score: 1.0,
        };
    }

    // Reject 'dev' mock token in production
    if (token === 'dev') {
        if (logger) {
            logger.warn('Turnstile', 'Rejected "dev" token in production environment');
        }
        return {
            success: false,
            errors: ['invalid-input-response'],
        };
    }

    // Missing secret key validation
    if (!secretKey) {
        if (logger) {
            logger.error('Turnstile', 'Missing Turnstile secret key');
        } else {
            console.error('Turnstile verification error: Missing secret key');
        }
        return {
            success: false,
            errors: ['missing-secret-key'],
        };
    }

    const formData = new FormData();
    formData.append('secret', secretKey);
    formData.append('response', token);
    if (remoteIP && remoteIP !== 'unknown') {
        formData.append('remoteip', remoteIP);
    }

    try {
        const response = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            {
                method: 'POST',
                body: formData,
            }
        );

        const result = (await response.json()) as {
            success: boolean;
            score?: number;
            'error-codes'?: string[];
            challenge_ts?: string;
            hostname?: string;
        };

        if (!result.success && logger) {
            logger.warn('Turnstile', `Verification failed with errors: ${result['error-codes']?.join(', ')}`);
        }

        return {
            success: result.success,
            score: result.score,
            errors: result['error-codes'],
        };
    } catch (error) {
        if (logger) {
            logger.error('Turnstile', 'Turnstile siteverify API exception', error);
        } else {
            console.error('Turnstile verification error:', error);
        }
        return {
            success: false,
            errors: ['verification-failed'],
        };
    }
}

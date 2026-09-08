/**
 * FreeFormer Zero Trust Authentication Guard
 * Cryptographically validates Cloudflare Access JWTs (RS256 via Web Crypto JWKS),
 * supports Bearer API_KEY authentication for backend integrations,
 * and provides dev-mode mock authentication.
 */

import type { Context, MiddlewareHandler } from 'hono';

export interface AuthenticatedUser {
  email: string;
  sub?: string;
  authMethod: 'cloudflare-access' | 'api-key' | 'local-dev';
}

interface CachedKey {
  key: CryptoKey;
  expiresAt: number;
}

// In-memory JWKS cache (1 hour TTL)
export const jwksCache = new Map<string, CachedKey>();

export function clearJwksCache() {
  jwksCache.clear();
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return atob(base64);
}

function base64UrlToUint8Array(str: string): Uint8Array {
  const binaryString = base64UrlDecode(str);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function getCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  const match = header.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Fetch and import RSA public key from Cloudflare Access JWKS endpoint
 */
async function getPublicKeyForKid(teamDomain: string, kid: string): Promise<CryptoKey | null> {
  const cleanDomain = teamDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const cacheKey = `${cleanDomain}:${kid}`;
  const now = Date.now();
  const cached = jwksCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    return cached.key;
  }

  try {
    const certsUrl = `https://${cleanDomain}/cdn-cgi/access/certs`;
    const res = await fetch(certsUrl);
    if (!res.ok) {
      console.warn(`[ZeroTrust:JWKS] Failed to fetch certs from ${certsUrl}: status ${res.status}`);
      return null;
    }
    const data = (await res.json()) as { keys?: Array<any> };
    const keys = data.keys || [];

    for (const keyData of keys) {
      if (keyData.kty === 'RSA' && keyData.kid) {
        try {
          const cryptoKey = await crypto.subtle.importKey(
            'jwk',
            {
              kty: keyData.kty,
              n: keyData.n,
              e: keyData.e,
              alg: keyData.alg || 'RS256',
              ext: true,
            },
            {
              name: 'RSASSA-PKCS1-v1_5',
              hash: 'SHA-256',
            },
            false,
            ['verify']
          );
          jwksCache.set(`${cleanDomain}:${keyData.kid}`, {
            key: cryptoKey,
            expiresAt: now + 60 * 60 * 1000, // 1 hour
          });
        } catch (keyErr) {
          console.warn(`[ZeroTrust:JWKS] Error importing key ${keyData.kid}:`, keyErr);
        }
      }
    }

    const matched = jwksCache.get(cacheKey);
    return matched ? matched.key : null;
  } catch (err) {
    console.error(`[ZeroTrust:JWKS] Error loading certs for ${cleanDomain}:`, err);
    return null;
  }
}

/**
 * Cryptographically verify Cloudflare Access JWT token
 */
export async function verifyCloudflareAccessJWT(
  token: string,
  teamDomain: string,
  expectedAud?: string
): Promise<AuthenticatedUser | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));

    if (header.alg !== 'RS256' || !header.kid) {
      return null;
    }

    // Check expiration
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < nowSec) {
      return null;
    }

    // Check Audience if configured
    if (expectedAud) {
      const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!auds.includes(expectedAud)) {
        return null;
      }
    }

    // Check Issuer
    const cleanDomain = teamDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (payload.iss && !payload.iss.includes(cleanDomain)) {
      return null;
    }

    // Retrieve public key
    const publicKey = await getPublicKeyForKid(cleanDomain, header.kid);
    if (!publicKey) {
      return null;
    }

    // Verify signature
    const dataToVerify = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signature = base64UrlToUint8Array(parts[2]);

    const isValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      publicKey,
      signature,
      dataToVerify
    );

    if (!isValid) {
      return null;
    }

    return {
      email: payload.email || payload.sub || 'authenticated-user@access',
      sub: payload.sub,
      authMethod: 'cloudflare-access',
    };
  } catch {
    return null;
  }
}

export type AuthBindings = {
  CF_ACCESS_ENABLED?: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  API_KEY?: string;
  DEV_MODE?: string;
  ENVIRONMENT?: string;
  [key: string]: any;
};

/**
 * Middleware requiring valid Cloudflare Zero Trust authentication or API_KEY
 */
export function requireZeroTrustAuth(): MiddlewareHandler<{ Bindings: AuthBindings; Variables: { user: AuthenticatedUser } }> {
  return async (c, next) => {
    const env = c.env;

    // 1. Check Bearer API Token (Service-to-Service / Admin CLI)
    const authHeader = c.req.header('authorization');
    if (authHeader && authHeader.startsWith('Bearer ') && env.API_KEY) {
      const token = authHeader.split(' ')[1];
      if (token === env.API_KEY) {
        c.set('user', {
          email: 'api-service@freeformer',
          authMethod: 'api-key',
        });
        return next();
      }
    }

    // 2. Local Dev Bypass
    const isDev =
      env.DEV_MODE === 'true' ||
      env.ENVIRONMENT === 'development';

    // 3. Extract Cloudflare Access JWT
    const jwtHeader = c.req.header('cf-access-jwt-assertion');
    const cookieHeader = c.req.header('cookie');
    const jwtCookie = getCookie(cookieHeader, 'CF_Authorization');
    const jwtToken = jwtHeader || jwtCookie;

    const teamDomain = env.CF_ACCESS_TEAM_DOMAIN;
    const expectedAud = env.CF_ACCESS_AUD;

    if (jwtToken && teamDomain) {
      const user = await verifyCloudflareAccessJWT(jwtToken, teamDomain, expectedAud);
      if (user) {
        c.set('user', user);
        return next();
      }
    }

    // Allow dev bypass if in development and no valid Access credentials provided
    if (isDev) {
      c.set('user', {
        email: 'dev@localhost',
        authMethod: 'local-dev',
      });
      return next();
    }

    // Direct header fallback if Cloudflare Access is in front and team domain isn't configured for isolate verification
    const cfUserEmail = c.req.header('cf-access-authenticated-user-email');
    if (cfUserEmail && env.CF_ACCESS_ENABLED === 'true' && !teamDomain) {
      c.set('user', {
        email: cfUserEmail,
        authMethod: 'cloudflare-access',
      });
      return next();
    }

    const acceptHeader = c.req.header('accept') || '';
    if (acceptHeader.includes('text/html')) {
      return c.html(
        `<!DOCTYPE html>
<html>
<head><title>401 Unauthorized - FreeFormer</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { background: #1e293b; padding: 32px; border-radius: 12px; border: 1px solid #334155; max-width: 440px; text-align: center; }
  h1 { font-size: 20px; color: #ef4444; margin-top: 0; }
  p { font-size: 14px; color: #94a3b8; line-height: 1.5; }
  code { background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #38bdf8; }
</style>
</head>
<body>
<div class="card">
  <h1>🔒 401 Unauthorized</h1>
  <p>This resource is protected by <strong>Cloudflare Zero Trust</strong>.</p>
  <p>Please authenticate through Cloudflare Access or provide a valid Bearer token in the <code>Authorization</code> header.</p>
</div>
</body>
</html>`,
        401
      );
    }

    return c.json(
      {
        success: false,
        error: 'Unauthorized. Cloudflare Zero Trust authentication or valid Bearer API key required.',
      },
      401
    );
  };
}

import { Sys1Pop } from '@sys1pop/sdk';

export interface Sys1PopSpamVerdict {
  isSpam: boolean;
  confidence: number;
  category: string;
  riskScore: number;
}

/**
 * Optionally evaluates ambiguous form submissions using Sys1Pop's edge decision engine.
 * If Sys1Pop is unconfigured or unavailable, returns null (graceful degradation).
 */
function normalizeSys1PopTarget(sys1popBinding: unknown, apiToken?: string) {
  if (typeof sys1popBinding === 'string') {
    const trimmed = sys1popBinding.trim();
    const endpoint = trimmed.startsWith('http://') || trimmed.startsWith('https://')
      ? trimmed
      : `https://${trimmed}`;
    return { endpoint, token: apiToken || undefined };
  }
  return { binding: sys1popBinding as any, token: apiToken || undefined };
}

export async function evaluateWithSys1Pop(
  sys1popBinding: unknown,
  formData: Record<string, any>,
  siteId: string,
  modelName: string = 'spam-detector-v1',
  apiToken?: string
): Promise<Sys1PopSpamVerdict | null> {
  if (!sys1popBinding) {
    return null;
  }

  const target = normalizeSys1PopTarget(sys1popBinding, apiToken);
  const sys1 = new Sys1Pop(target);
  if (!sys1.isConfigured()) {
    return null;
  }

  // Extract contact fields and textual state
  const name = String(formData.name || formData.fullname || '').trim();
  const email = String(formData.email || '').trim();
  const message = Object.entries(formData)
    .filter(([k]) => !['_hp', 'website', 'company_url', 'honeypot'].includes(k.toLowerCase()))
    .map(([k, v]) => `${k}: ${v}`)
    .join(' | ');

  try {
    const res = await sys1.decide({
      model: modelName,
      state: `Site: ${siteId} | Name: ${name} | Email: ${email} | Content: ${message}`,
      questions: [
        { type: 'boolean', id: 'is_spam' },
        {
          type: 'choice',
          id: 'spam_category',
          options: [
            'legitimate_inquiry',
            'commercial_sales_pitch',
            'seo_backlink_spam',
            'crypto_phishing',
            'automated_bot_gibberish',
          ],
        },
        { type: 'score', id: 'risk_score', min: 1, max: 5 },
      ],
    });

    const isSpam = res.getBoolean('is_spam') ?? false;
    const confidence = res.getProbability('is_spam') ?? 0.5;
    const category = res.getChoice('spam_category') ?? 'legitimate_inquiry';
    const riskScore = res.getScore('risk_score') ?? 1.0;

    return {
      isSpam,
      confidence,
      category,
      riskScore,
    };
  } catch (err) {
    console.warn('[FreeFormer] Sys1Pop decision check failed, gracefully falling back to heuristics:', err);
    return null;
  }
}

export interface Sys1PopProbeResult {
  configured: boolean;
  endpointType: 'binding' | 'http' | 'none';
  model: string;
  tokenConfigured: boolean;
  success: boolean;
  latencyMs?: number;
  cached?: boolean;
  verdict?: Sys1PopSpamVerdict;
  error?: string;
}

/**
 * Executes a programmatic live probe to test the Sys1Pop edge decision service binding / endpoint,
 * model availability, authorization, and inference latency.
 */
export async function probeSys1Pop(
  sys1popBinding: unknown,
  siteId: string = 'default',
  modelName: string = 'spam-detector-v1',
  apiToken?: string
): Promise<Sys1PopProbeResult> {
  if (!sys1popBinding) {
    return {
      configured: false,
      endpointType: 'none',
      model: modelName,
      tokenConfigured: !!apiToken,
      success: false,
      error: 'SYS1POP service binding or endpoint is not configured',
    };
  }

  const endpointType = typeof sys1popBinding === 'string' ? 'http' : 'binding';
  const target = normalizeSys1PopTarget(sys1popBinding, apiToken);
  const sys1 = new Sys1Pop(target);
  if (!sys1.isConfigured()) {
    return {
      configured: false,
      endpointType,
      model: modelName,
      tokenConfigured: !!apiToken,
      success: false,
      error: 'Sys1Pop client failed to configure from binding or endpoint',
    };
  }

  const t0 = Date.now();
  try {
    const res = await sys1.decide({
      model: modelName,
      state: `Site: ${siteId} | Diagnostic probe verifying live edge connection and model status.`,
      questions: [
        { type: 'boolean', id: 'is_spam' },
        {
          type: 'choice',
          id: 'spam_category',
          options: [
            'legitimate_inquiry',
            'commercial_sales_pitch',
            'seo_backlink_spam',
            'crypto_phishing',
            'automated_bot_gibberish',
          ],
        },
        { type: 'score', id: 'risk_score', min: 1, max: 5 },
      ],
    });

    const latencyMs = Date.now() - t0;
    const isSpam = res.getBoolean('is_spam') ?? false;
    const confidence = res.getProbability('is_spam') ?? 0.5;
    const category = res.getChoice('spam_category') ?? 'legitimate_inquiry';
    const riskScore = res.getScore('risk_score') ?? 1.0;

    return {
      configured: true,
      endpointType,
      model: modelName,
      tokenConfigured: !!apiToken,
      success: true,
      latencyMs,
      cached: res.cached,
      verdict: {
        isSpam,
        confidence,
        category,
        riskScore,
      },
    };
  } catch (err: any) {
    const latencyMs = Date.now() - t0;
    return {
      configured: true,
      endpointType,
      model: modelName,
      tokenConfigured: !!apiToken,
      success: false,
      latencyMs,
      error: err?.message || String(err),
    };
  }
}


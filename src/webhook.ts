/**
 * FreeFormer Universal Webhook Engine
 * Dispatches structured webhook envelopes compatible with Zapier Catch Hooks,
 * Make (Integromat), n8n, Slack, and custom webhooks.
 * Includes HMAC-SHA256 payload signing and temporary signed R2 download links.
 */

import type { Logger } from './logger';
import { createSignedDownloadUrl, type StoredAttachment } from './files';

export interface WebhookAttachmentInfo {
  filename: string;
  size: number;
  mimeType: string;
  downloadUrl?: string;
}

export interface UniversalWebhookPayload {
  event: string;
  id: string;
  formId: string;
  siteId: string;
  timestamp: string;
  data: Record<string, any>;
  attachments: WebhookAttachmentInfo[];
  metadata: {
    ip: string;
    userAgent: string;
    turnstileScore?: number;
  };
}

/**
 * Computes an HMAC-SHA256 signature for the webhook payload
 */
export async function signWebhookPayload(payloadString: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadString));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Builds the standardized webhook payload with signed download URLs for R2 attachments
 */
export async function buildWebhookPayload(
  submission: {
    submissionId: string;
    formId: string;
    siteId: string;
    data: Record<string, any>;
    metadata: {
      ip: string;
      userAgent: string;
      timestamp: string;
      turnstileScore?: number;
    };
    attachments?: StoredAttachment[];
  },
  workerBaseUrl?: string,
  secret?: string,
  signedUrlTtlSeconds?: number
): Promise<UniversalWebhookPayload> {
  const attachments: WebhookAttachmentInfo[] = [];

  if (submission.attachments && submission.attachments.length > 0) {
    for (const att of submission.attachments) {
      let downloadUrl: string | undefined = undefined;
      if (workerBaseUrl && secret) {
        downloadUrl = await createSignedDownloadUrl(
          workerBaseUrl,
          att.key,
          secret,
          signedUrlTtlSeconds || 900
        );
      }
      attachments.push({
        filename: att.filename,
        size: att.size,
        mimeType: att.mimeType,
        downloadUrl,
      });
    }
  }

  return {
    event: 'form_submission',
    id: submission.submissionId,
    formId: submission.formId,
    siteId: submission.siteId,
    timestamp: submission.metadata.timestamp || new Date().toISOString(),
    data: submission.data,
    attachments,
    metadata: {
      ip: submission.metadata.ip,
      userAgent: submission.metadata.userAgent,
      turnstileScore: submission.metadata.turnstileScore,
    },
  };
}

/**
 * Dispatches an HTTP POST webhook request with HMAC signatures
 */
export async function dispatchWebhook(
  webhookUrl: string,
  payload: UniversalWebhookPayload,
  secret?: string,
  logger?: Logger
): Promise<{ success: boolean; status?: number; error?: string }> {
  const jsonBody = JSON.stringify(payload);
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-FreeFormer-Event': payload.event || 'form_submission',
    'X-FreeFormer-Timestamp': String(Math.floor(Date.now() / 1000)),
  };

  if (secret) {
    try {
      const signature = await signWebhookPayload(jsonBody, secret);
      headers['X-FreeFormer-Signature'] = `sha256=${signature}`;
    } catch (sigErr) {
      logger?.warn('Webhook', 'Failed to compute HMAC signature', sigErr);
    }
  }

  logger?.debug('Webhook', `Dispatching to "${webhookUrl}" | Event: "${payload.event}"`);

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers,
      body: jsonBody,
    });

    if (!res.ok) {
      const text = await res.text();
      logger?.error('Webhook', `Failed with status ${res.status}: ${text}`);
      return { success: false, status: res.status, error: text };
    }

    logger?.info('Webhook', `Successfully delivered to "${webhookUrl}" (status ${res.status})`);
    return { success: true, status: res.status };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    logger?.error('Webhook', `Exception during dispatch: ${errorMsg}`);
    return { success: false, error: errorMsg };
  }
}

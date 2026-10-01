import { describe, it, expect } from 'vitest';
import { evaluateWithSys1Pop, probeSys1Pop } from './sys1pop';

describe('FreeFormer Sys1Pop Progressive Enhancement', () => {
  it('returns null when SYS1POP binding is undefined (graceful degradation)', async () => {
    const result = await evaluateWithSys1Pop(undefined, { message: 'hello' }, 'test-site');
    expect(result).toBeNull();
  });

  it('correctly maps decision and defaults to spam-detector-v1 model', async () => {
    let capturedBody: any = null;
    const mockBinding = {
      async fetch(url: string, init: any) {
        capturedBody = JSON.parse(init.body);
        return new Response(
          JSON.stringify({
            decisions: {
              is_spam: { type: 'boolean', value: true, probability: 0.95 },
              spam_category: { type: 'choice', winner: 'crypto_phishing', confidence: 0.9, distribution: {} },
              risk_score: { type: 'score', expected_value: 4.8, distribution: [] },
            },
            metrics: { tokenize_ms: 1.0, forward_pass_ms: 15.0, total_ms: 18.0 },
            cached: false,
            model_id: 'spam-detector-v1',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    };

    const result = await evaluateWithSys1Pop(
      mockBinding,
      { name: 'Spammer', email: 'bot@spam.com', message: 'Send crypto to 0x123' },
      'test-site'
    );

    expect(capturedBody?.model).toBe('spam-detector-v1');
    expect(result).not.toBeNull();
    expect(result?.isSpam).toBe(true);
    expect(result?.category).toBe('crypto_phishing');
    expect(result?.riskScore).toBe(4.8);
    expect(result?.confidence).toBe(0.95);
  });

  it('allows overriding model name via parameter', async () => {
    let capturedModel: string | null = null;
    const mockBinding = {
      async fetch(url: string, init: any) {
        capturedModel = JSON.parse(init.body)?.model;
        return new Response(
          JSON.stringify({
            decisions: {
              is_spam: { type: 'boolean', value: false, probability: 0.1 },
            },
            metrics: { tokenize_ms: 1.0, forward_pass_ms: 10.0, total_ms: 12.0 },
            cached: false,
            model_id: capturedModel,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    };

    await evaluateWithSys1Pop(
      mockBinding,
      { message: 'Hello team' },
      'test-site',
      'custom-spam-model'
    );

    expect(capturedModel).toBe('custom-spam-model');
  });

  it('attaches Bearer Authorization header when apiToken is provided', async () => {
    let capturedHeaders: any = null;
    const mockBinding = {
      async fetch(url: string, init: any) {
        capturedHeaders = init.headers;
        return new Response(
          JSON.stringify({
            decisions: {
              is_spam: { type: 'boolean', value: false, probability: 0.05 },
            },
            metrics: { tokenize_ms: 1.0, forward_pass_ms: 10.0, total_ms: 12.0 },
            cached: false,
            model_id: 'spam-detector-v1',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    };

    await evaluateWithSys1Pop(
      mockBinding,
      { message: 'Hello team' },
      'test-site',
      'spam-detector-v1',
      'sys1-secret-token-xyz'
    );

    expect(capturedHeaders).toBeDefined();
    expect(capturedHeaders['Authorization']).toBe('Bearer sys1-secret-token-xyz');
  });

  it('omits Authorization header when apiToken is omitted', async () => {
    let capturedHeaders: any = null;
    const mockBinding = {
      async fetch(url: string, init: any) {
        capturedHeaders = init.headers;
        return new Response(
          JSON.stringify({
            decisions: {
              is_spam: { type: 'boolean', value: false, probability: 0.05 },
            },
            metrics: { tokenize_ms: 1.0, forward_pass_ms: 10.0, total_ms: 12.0 },
            cached: false,
            model_id: 'spam-detector-v1',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    };

    await evaluateWithSys1Pop(
      mockBinding,
      { message: 'Hello team' },
      'test-site'
    );

    expect(capturedHeaders).toBeDefined();
    expect(capturedHeaders['Authorization']).toBeUndefined();
  });

  it('gracefully returns null if SYS1POP throws an error (fail-safe)', async () => {
    const failingBinding = {
      async fetch() {
        throw new Error('Network timeout');
      },
    };

    const result = await evaluateWithSys1Pop(
      failingBinding,
      { message: 'Test message' },
      'test-site'
    );

    expect(result).toBeNull();
  });

  describe('probeSys1Pop diagnostic testing', () => {
    it('returns unconfigured status when binding is undefined', async () => {
      const probe = await probeSys1Pop(undefined, 'test-site', 'spam-detector-v1');
      expect(probe.configured).toBe(false);
      expect(probe.success).toBe(false);
      expect(probe.endpointType).toBe('none');
      expect(probe.error).toContain('not configured');
    });

    it('returns successful probe with verdict and latency when Sys1Pop succeeds', async () => {
      let sentAuthHeader: string | undefined;
      const mockBinding = {
        async fetch(url: string, init: any) {
          sentAuthHeader = init.headers?.['Authorization'];
          return new Response(
            JSON.stringify({
              decisions: {
                is_spam: { type: 'boolean', value: false, probability: 0.02 },
                spam_category: { type: 'choice', winner: 'legitimate_inquiry', confidence: 0.98, distribution: {} },
                risk_score: { type: 'score', expected_value: 1.1, distribution: [] },
              },
              metrics: { tokenize_ms: 1.2, forward_pass_ms: 12.0, total_ms: 14.5 },
              cached: true,
              model_id: 'spam-detector-v1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        },
      };

      const probe = await probeSys1Pop(mockBinding, 'test-site', 'spam-detector-v1', 'test-token');
      expect(probe.configured).toBe(true);
      expect(probe.success).toBe(true);
      expect(probe.endpointType).toBe('binding');
      expect(probe.tokenConfigured).toBe(true);
      expect(sentAuthHeader).toBe('Bearer test-token');
      expect(probe.latencyMs).toBeTypeOf('number');
      expect(probe.verdict?.isSpam).toBe(false);
      expect(probe.verdict?.category).toBe('legitimate_inquiry');
      expect(probe.cached).toBe(true);
    });

    it('returns error details when Sys1Pop returns 404 or fails', async () => {
      const errorBinding = {
        async fetch() {
          return new Response("Model 'unknown-model' not found in R2 bucket 'MODELS'", {
            status: 404,
            headers: { 'Content-Type': 'text/plain' },
          });
        },
      };

      const probe = await probeSys1Pop(errorBinding, 'test-site', 'unknown-model');
      expect(probe.configured).toBe(true);
      expect(probe.success).toBe(false);
      expect(probe.error).toContain('404');
    });
  });
});

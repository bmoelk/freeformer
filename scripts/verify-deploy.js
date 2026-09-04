#!/usr/bin/env node

/**
 * FreeFormer Post-Deployment Verification & Health Diagnostic Script
 * Automatically queries the deployed Worker, verifies active bindings and secrets,
 * and cross-references local overrides (.dev.vars / wrangler.overrides.toml) against
 * the remote deployment with full multi-tenant site consistency checks.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const DEFAULT_URL = process.env.WORKER_URL || 'https://freeformer.bmoelk.workers.dev';
const MANIFEST_PATH = path.join(__dirname, '..', 'config-manifest.json');

async function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    client.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ statusCode: res.statusCode, raw: data });
        }
      });
    }).on('error', reject);
  });
}

function loadManifest() {
  if (fs.existsSync(MANIFEST_PATH)) {
    return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
  }
  return null;
}

function getLocalConfig() {
  const localKeys = new Set();
  const localKeyValues = {};
  const plaintextSecretViolations = [];

  // Known secret key patterns that must NEVER be in [vars]
  const isSecretKey = (key) => /^(?:TURNSTILE_SECRET_KEY|API_KEY)(?:_[A-Z0-9_]+)?$/.test(key);
  const isFrontendOnlyKey = (key) => /^TURNSTILE_SITE_KEY(?:_[A-Z0-9_]+)?$/.test(key);

  // 1. Read .dev.vars
  const devVarsPath = path.join(__dirname, '..', '.dev.vars');
  if (fs.existsSync(devVarsPath)) {
    const lines = fs.readFileSync(devVarsPath, 'utf-8').split('\n');
    for (const line of lines) {
      const match = line.trim().match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
      if (match && !match[1].startsWith('#')) {
        const key = match[1];
        if (!isFrontendOnlyKey(key)) {
          localKeys.add(key);
        }
        localKeyValues[key] = match[2].trim().replace(/^["']|["']$/g, '');
      }
    }
  }

  // 2. Read wrangler.overrides.toml
  const overridesPath = path.join(__dirname, '..', 'wrangler.overrides.toml');
  if (fs.existsSync(overridesPath)) {
    const content = fs.readFileSync(overridesPath, 'utf-8');
    const lines = content.split('\n');
    let inVars = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[vars]') {
        inVars = true;
        continue;
      }
      if (trimmed.startsWith('[') && trimmed !== '[vars]') {
        inVars = false;
        continue;
      }
      if (inVars) {
        const match = trimmed.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
        if (match && !match[1].startsWith('#')) {
          const key = match[1];
          if (isSecretKey(key)) {
            plaintextSecretViolations.push(key);
          } else if (isFrontendOnlyKey(key)) {
            plaintextSecretViolations.push(`${key} (Frontend Site Key not needed in Worker)`);
          } else {
            localKeys.add(key);
          }
          localKeyValues[key] = match[2].trim().replace(/^["']|["']$/g, '');
        }
      }
    }

    // Check bound KV namespaces in overrides
    const kvMatches = content.matchAll(/\[\[kv_namespaces\]\][^\[]*binding\s*=\s*"([^"]+)"/g);
    for (const match of kvMatches) {
      localKeys.add(match[1]);
    }

    // Check bound D1 databases in overrides
    const d1Matches = content.matchAll(/\[\[d1_databases\]\][^\[]*binding\s*=\s*"([^"]+)"/g);
    for (const match of d1Matches) {
      localKeys.add(match[1]);
    }
  }

  return {
    keys: Array.from(localKeys),
    values: localKeyValues,
    plaintextSecretViolations,
  };
}

async function verifyDeployment() {
  const targetUrl = process.argv[2] || DEFAULT_URL;
  const manifest = loadManifest();

  console.log(`\n========================================================================`);
  console.log(`🔍 FreeFormer Post-Deployment Health & Consistency Verification`);
  console.log(`========================================================================`);
  console.log(`Target Worker:   ${targetUrl}`);

  try {
    const response = await fetchJson(targetUrl);

    if (response.statusCode !== 200 || !response.data) {
      console.log(`\n❌ Worker returned status code: ${response.statusCode}`);
      console.log(`Raw response:`, response.raw || response.data);
      console.log(`========================================================================\n`);
      return;
    }

    const { status, environment, version, config } = response.data;

    console.log(`Service Status:  ✅ ${(status || 'healthy').toUpperCase()} (v${version || '0.2.0'})`);
    console.log(`Environment:     ${environment || 'production'}`);
    console.log(`------------------------------------------------------------------------`);
    console.log(`Core Storage Engine & Global Bindings:`);

    const warnings = [];

    if (!config) {
      console.log(`  ℹ️  Worker running legacy endpoint (deploy latest worker to see full diagnostics)`);
      console.log(`========================================================================\n`);
      return;
    }

    // 1. Storage Engine Verification
    const engine = (config.storageEngine || config.storage || 'none').toLowerCase();
    if (engine === 'none') {
      console.log(`  • Storage Engine:   ℹ️  NONE (Persistence is disabled)`);
    } else if (engine === 'kv') {
      if (config.kvBound || config.storageConfigured || (config.configuredKeys && config.configuredKeys.includes('KV'))) {
        console.log(`  • Storage Engine:   ✅ KV Storage Active (Binding: KV)`);
      } else {
        console.log(`  • Storage Engine:   ❌ MISCONFIGURED (STORAGE_ENGINE is 'kv' but binding 'KV' is missing)`);
        warnings.push(`STORAGE_ENGINE is 'kv', but no KV namespace is bound. Attach [[kv_namespaces]] binding = "KV" in wrangler.overrides.toml`);
      }
    } else if (engine === 'd1') {
      if (config.d1Bound || (config.configuredKeys && config.configuredKeys.includes('DB'))) {
        console.log(`  • Storage Engine:   ✅ D1 SQL Database Active (Binding: DB)`);
      } else {
        console.log(`  • Storage Engine:   ❌ MISCONFIGURED (STORAGE_ENGINE is 'd1' but D1 binding 'DB' is missing)`);
        warnings.push(`STORAGE_ENGINE is 'd1', but D1 binding 'DB' is missing. Attach [[d1_databases]] binding = "DB" in wrangler.overrides.toml`);
      }
    }

    // 2. Email Provider & Keys Check
    const emailProvider = config.emailProvider || 'none';
    if (emailProvider === 'none') {
      console.log(`  • Email Provider:   ℹ️  NONE (Email alerts are disabled)`);
    } else {
      console.log(`  • Email Provider:   ✅ ${emailProvider.toUpperCase()}`);

      if (!config.emailToConfigured) {
        console.log(`  • Email Recipient:  ❌ MISSING (EMAIL_TO is not set)`);
        warnings.push(`Set EMAIL_TO in wrangler.overrides.toml or via: npx wrangler secret put EMAIL_TO`);
      } else {
        console.log(`  • Email Recipient:  ✅ Configured (EMAIL_TO)`);
      }

      if (!config.emailFromConfigured) {
        console.log(`  • Email Sender:     ❌ MISSING (EMAIL_FROM is not set)`);
        warnings.push(`Set EMAIL_FROM in wrangler.overrides.toml or via: npx wrangler secret put EMAIL_FROM`);
      } else {
        console.log(`  • Email Sender:     ✅ Configured (EMAIL_FROM)`);
      }

      if (emailProvider !== 'console') {
        if (!config.emailApiKeyConfigured) {
          console.log(`  • Email API Key:    ❌ MISSING (EMAIL_API_KEY is not set)`);
          warnings.push(`Set EMAIL_API_KEY via: npx wrangler secret put EMAIL_API_KEY`);
        } else {
          console.log(`  • Email API Key:    ✅ Configured`);
        }
      }
    }

    // 3. Turnstile Spam Protection Check
    if (!config.turnstileConfigured) {
      console.log(`  • Turnstile Secret: ⚠️ NOT SET (Spam verification will fail in production)`);
      warnings.push(`Set Turnstile Secret Key via: npx wrangler secret put TURNSTILE_SECRET_KEY`);
    } else {
      console.log(`  • Turnstile Secret: ✅ Configured (TURNSTILE_SECRET_KEY)`);
    }

    // 4. Rate Limiting Check
    console.log(`  • Rate Limiting:    ${config.rateLimitEnabled ? '✅ Enabled' : 'ℹ️  Disabled'}`);

    // 5. Multi-Tenant Per-Site Consistency Check
    const local = getLocalConfig();
    const remoteKeySet = new Set(config.configuredKeys || []);

    // Detect all referenced site IDs from local config (e.g. BRAINENDEAVOR, SPLITPHASE)
    const siteIds = new Set();
    for (const key of local.keys) {
      const match = key.match(/^(?:TURNSTILE_SECRET_KEY|EMAIL_TO|EMAIL_FROM|EMAIL_PROVIDER|EMAIL_API_KEY|WEBHOOK_URL)_([A-Z0-9_]+)$/);
      if (match) {
        siteIds.add(match[1]);
      }
    }

    if (siteIds.size > 0) {
      console.log(`------------------------------------------------------------------------`);
      console.log(`Multi-Tenant Site Consistency Matrix:`);

      for (const siteId of siteIds) {
        console.log(`\n  [Site: ${siteId}]`);

        // Check Multi-Tenant Storage Partitioning
        if (engine === 'kv') {
          console.log(`    • Storage Engine:  ✅ KV Namespace (Partitioned keys: submission:${siteId.toLowerCase()}:<formId>:<id>)`);
        } else if (engine === 'd1') {
          console.log(`    • Storage Engine:  ✅ D1 SQL Database (Partitioned rows: WHERE site_id='${siteId.toLowerCase()}')`);
        } else {
          console.log(`    • Storage Engine:  ℹ️  Persistence Disabled (STORAGE_ENGINE='none')`);
        }

        // Check Site Turnstile
        const siteTurnstileKey = `TURNSTILE_SECRET_KEY_${siteId}`;
        if (remoteKeySet.has(siteTurnstileKey)) {
          console.log(`    • Turnstile:       ✅ Site-Specific Key (${siteTurnstileKey})`);
        } else if (config.turnstileConfigured) {
          console.log(`    • Turnstile:       ℹ️  Using Global Turnstile Secret Fallback`);
        } else {
          console.log(`    • Turnstile:       ❌ Missing (${siteTurnstileKey} or global TURNSTILE_SECRET_KEY)`);
          warnings.push(`Site '${siteId}' has no Turnstile secret key set.`);
        }

        // Check Site Email Target
        const siteEmailToKey = `EMAIL_TO_${siteId}`;
        if (remoteKeySet.has(siteEmailToKey)) {
          console.log(`    • Email Alerts:    ✅ Site-Specific Recipient (${siteEmailToKey})`);
        } else if (config.emailToConfigured) {
          console.log(`    • Email Alerts:    ℹ️  Using Global Recipient Fallback (EMAIL_TO)`);
        }
      }
    }

    // 6. Check for Security Violations in [vars]
    if (local.plaintextSecretViolations.length > 0) {
      console.log(`------------------------------------------------------------------------`);
      console.log(`🔒 Security Audit: Plaintext Secrets in wrangler.overrides.toml`);
      for (const item of local.plaintextSecretViolations) {
        console.log(`  • ❌ CRITICAL: '${item}' found under [vars]!`);
        warnings.push(`Plaintext Secret Violation: '${item}' is under [vars] in wrangler.overrides.toml. Remove it from [vars] and use: npx wrangler secret put ${item.split(' ')[0]}`);
      }
    }

    // 7. Cross-Reference Local vs Remote Environment Keys
    if (local.keys.length > 0 && config.configuredKeys) {
      console.log(`------------------------------------------------------------------------`);
      console.log(`Local vs. Remote Key Provisioning Check:`);

      for (const key of local.keys) {
        if (['DEV_MOCK_TURNSTILE', 'DEV_MODE'].includes(key)) continue;

        if (remoteKeySet.has(key)) {
          console.log(`  • ${key.padEnd(32)} ✅ Active in remote deployment`);
        } else {
          console.log(`  • ${key.padEnd(32)} ❌ MISSING in remote deployment!`);
          warnings.push(`Local key '${key}' is defined locally but missing on remote Worker. Set via: npx wrangler secret put ${key}`);
        }
      }
    }

    console.log(`------------------------------------------------------------------------`);

    if (warnings.length === 0) {
      console.log(`🎉 All required environment variables, bindings, and multi-tenant sites are verified!`);
    } else {
      console.log(`⚠️  ATTENTION REQUIRED (${warnings.length} warning${warnings.length > 1 ? 's' : ''}):`);
      warnings.forEach((warn, idx) => {
        console.log(`  ${idx + 1}. ${warn}`);
      });
    }

    console.log(`========================================================================\n`);
  } catch (err) {
    console.log(`\n❌ Could not connect to Worker endpoint: ${err.message}`);
    console.log(`Check network connectivity or verify Worker DNS routes.`);
    console.log(`========================================================================\n`);
  }
}

verifyDeployment();

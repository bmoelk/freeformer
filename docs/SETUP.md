# FreeFormer Setup Guide

This guide will walk you through setting up FreeFormer from scratch.

## Prerequisites

- A Cloudflare account
- Node.js 18+ installed
- npm or yarn

## Step 1: Install Dependencies

```bash
cd freeformer
npm install
```

## Step 2: Set Up Turnstile

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Navigate to **Turnstile** in the sidebar
3. Click **Add Site**
4. Configure your site:
   - **Site name**: Your site name (e.g., "My Contact Form")
   - **Domain**: Your domain or `localhost` for testing
   - **Widget Mode**: Choose "Managed" (recommended)
5. Click **Create**
6. Copy your **Site Key** and **Secret Key**

## Step 3: Configure Local Development

1. Copy the example environment file:
```bash
cp .dev.vars.example .dev.vars
```

2. Edit `.dev.vars` and add your Turnstile secret key:
```
TURNSTILE_SECRET_KEY=your-actual-secret-key-here
```

## Step 4: Choose Your Storage Backend

Set `STORAGE_ENGINE = "kv"`, `"d1"`, or `"none"` in your `wrangler.overrides.toml` (or `.dev.vars` for local dev).

### Option A: Workers KV Storage (Recommended for serverless simplicity)

1. Create a KV namespace:
```bash
npx wrangler kv namespace create KV
```

2. Add the binding and storage engine to your `wrangler.overrides.toml`:
```toml
[vars]
STORAGE_ENGINE = "kv"

[[kv_namespaces]]
binding = "KV"
id = "your-kv-namespace-id"
```

*(For multi-tenant setups, you can also add dedicated per-site namespaces like `binding = "KV_BRAINENDEAVOR"`).*

### Option B: Cloudflare D1 SQL Database (Recommended for complex relational querying)

1. Create a D1 database:
```bash
npx wrangler d1 create freeformer-db
```

2. Initialize the database schema:
```bash
npx wrangler d1 execute freeformer-db --remote --file=./schema.sql
```

3. Add the binding and storage engine to your `wrangler.overrides.toml`:
```toml
[vars]
STORAGE_ENGINE = "d1"

[[d1_databases]]
binding = "DB"
database_name = "freeformer-db"
database_id = "your-d1-database-uuid"
```

*(FreeFormer automatically partitions submissions in D1 across multiple tenants via the `site_id` column and `idx_site_form_created_at` index).*

## Step 5: Test Locally

Start the development server:
```bash
npm run dev
```

The worker will be available at `http://localhost:8787`

Test the health endpoint:
```bash
curl http://localhost:8787
```

## Step 6: Deploy to Cloudflare

1. Set your production Turnstile secret:
```bash
wrangler secret put TURNSTILE_SECRET_KEY
# Enter your secret key when prompted
```

2. Deploy the worker:
```bash
npm run deploy:prod
# or: npx wrangler deploy -c wrangler.overrides.toml
```

3. Note your worker URL (e.g., `https://freeformer.your-subdomain.workers.dev` or custom domain).

## Step 7: Configure Custom Domains & Multi-Site Routes (Optional)

FreeFormer supports routing multiple websites and custom domains into a single Worker instance. This allows you to centralize form processing while keeping forms branded under each site's own domain.

### Option A: Custom Domains (Recommended)

You can assign dedicated subdomains (e.g., `contact.splitphase.io`, `contact.brainendeavor.com`) directly to your Worker. Cloudflare automatically handles DNS provisioning and SSL/TLS certificates.

Add the `routes` array to `wrangler.overrides.toml`:

```toml
# wrangler.overrides.toml

routes = [
  { pattern = "contact.splitphase.io", custom_domain = true },
  { pattern = "contact.brainendeavor.com", custom_domain = true },
  { pattern = "contact.drawdown.pro", custom_domain = true }
]
```

> [!NOTE]
> **Why does Wrangler warn about removing routes during deploy?**
> When you run `wrangler deploy`, Wrangler compares the routes currently assigned to your Worker in Cloudflare against the routes declared in your deployment configuration file (`wrangler.overrides.toml`). If a custom domain was configured previously or in the Cloudflare Dashboard but is omitted from your local config, Wrangler will warn that it is scheduled for removal. Adding all active custom domains to the `routes` array in `wrangler.overrides.toml` prevents accidental detachment.

### Option B: Zone Path Routes (Same-Origin)

If your website apex domains are proxied through Cloudflare DNS (Orange Clouded), you can route a subpath directly to the FreeFormer worker:

```toml
# wrangler.overrides.toml

routes = [
  { pattern = "splitphase.io/api/contact*", zone_name = "splitphase.io" },
  { pattern = "brainendeavor.com/api/contact*", zone_name = "brainendeavor.com" }
]
```

**Benefits of Same-Origin Path Routes:**
- Frontend JavaScript `fetch()` calls to `/api/contact/submit` are completely same-origin—no CORS preflight requests or CORS configuration required.

### Multi-Domain CORS Considerations

- **Standard HTML Form Submissions (`<form action="..." method="POST">`)**: Native browser form submissions do not enforce CORS restrictions. Forms from any domain can post directly to your custom domain or `*.workers.dev` endpoint.
- **JavaScript `fetch()` / AJAX Submissions**: When making cross-origin `fetch()` requests (including from `brainendeavor.com` to `contact.brainendeavor.com`), ensure all submitting origins are included in `ALLOWED_ORIGINS`:
  ```toml
  [vars]
  ALLOWED_ORIGINS = "https://splitphase.io,https://www.splitphase.io,https://brainendeavor.com"
  ```

## Step 8: Integrate with Your Website

1. Open `examples/example.html` in your editor

2. Update the configuration:
   - Replace `YOUR_TURNSTILE_SITE_KEY` with your Turnstile site key
   - Replace `https://your-worker.workers.dev/submit` with your actual worker URL (or custom domain `https://contact.yourdomain.com/submit`)

3. Upload `examples/example.html` to your static hosting (GitHub Pages, Netlify, etc.)

## Step 9: Environment Variables & Secrets Reference List

All configuration parameters and secrets supported by FreeFormer are summarized below. You can specify non-sensitive environment variables in `.dev.vars` (or Cloudflare Dashboard), and sensitive secrets via `npx wrangler secret put KEY_NAME`.

<!-- CONFIG_TABLE_START -->

| Variable / Secret Name | Kind | Required? | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | Var | Optional | `production` | Deployment mode (development / staging / production). |
| `LOG_LEVEL` | Var | Optional | `warn` | Logging verbosity level (debug, info, warn, error, none). Inferred from ENVIRONMENT if omitted (production=warn, staging=info, development=debug). |
| `ALLOWED_ORIGINS` | Var | Optional | `*` | Comma-separated list of allowed CORS origins (e.g. https://example.com,https://staging.example.com). |
| `RATE_LIMIT_ENABLED` | Var | Optional | `false` | Enable/disable IP rate limiting (true / false). |
| `RATE_LIMIT_REQUESTS` | Var | Optional | `10` | Max requests allowed per rate limit window per IP. |
| `RATE_LIMIT_WINDOW` | Var | Optional | `60` | Duration of rate limit window in seconds. |
| `STORAGE_ENGINE` | Var | Yes | `kv` | Primary storage engine for form submissions (kv, d1, none). |
| `EMAIL_PROVIDER` | Var | Optional | `none` | Outbound email provider (none, console, mailtrap, resend, sendgrid, mailgun). |
| `EMAIL_FROM` | Var/Secret | Required (Required when EMAIL_PROVIDER is not 'none' or 'console') | - | Outbound 'From' email address (e.g. contact@yourdomain.com). |
| `EMAIL_TO` | Var/Secret | Required (EMAIL_PROVIDER is not 'none') | - | Target notification recipient email address (e.g. alerts@yourdomain.com). |
| `EMAIL_API_KEY` | Secret | Required (EMAIL_PROVIDER is not 'none' or 'console') | - | API key for Mailtrap, Resend, SendGrid, or Mailgun. |
| `EMAIL_API_KEY_${SITE_ID}` | Secret | Optional | - | Per-site email provider API key override (e.g. EMAIL_API_KEY_BRAINENDEAVOR). |
| `EMAIL_TO_${SITE_ID}` | Var/Secret | Optional | - | Per-site notification recipient email override (e.g. EMAIL_TO_BRAINENDEAVOR). |
| `EMAIL_FROM_${SITE_ID}` | Var/Secret | Optional | - | Per-site 'From' email sender override (e.g. EMAIL_FROM_BRAINENDEAVOR). |
| `EMAIL_PROVIDER_${SITE_ID}` | Var | Optional | - | Per-site email provider override (e.g. EMAIL_PROVIDER_BRAINENDEAVOR). |
| `TURNSTILE_SECRET_KEY` | Secret | Yes | - | Global default Cloudflare Turnstile secret key. |
| `TURNSTILE_SECRET_KEY_${SITE_ID}` | Secret | Optional | - | Per-site Turnstile secret key (e.g. TURNSTILE_SECRET_KEY_MYSITE). |
| `API_KEY` | Secret | Required (Required for admin GET endpoints (/submissions) or /email-test; optional for public submissions which only require a Turnstile token) | - | Bearer API token for admin GET endpoints (/submissions, /submission/:id, /email-test) and webhook signing. Public form submissions only require a Turnstile token. |
| `WEBHOOK_URL` | Var/Secret | Optional | - | Global fallback webhook POST URL triggered on submission events. |
| `WEBHOOK_URL_${SITE_ID}` | Var/Secret | Optional | - | Per-site webhook POST URL (e.g. WEBHOOK_URL_MYSITE). |
| `MAILGUN_DOMAIN` | Var/Secret | Required (EMAIL_PROVIDER is 'mailgun') | - | Mailgun sending domain (required when using Mailgun). |
| `MAILTRAP_INBOX_ID` | Var/Secret | Required (Using Mailtrap Sandbox Testing Mode) | - | Mailtrap inbox identifier for sandbox testing mode. |
| `PROTECTED_FIELDS` | Var | Optional | - | Global comma-separated list of form fields to protect from notification emails (supports wildcards, e.g. ssn,tax_id,utm_*,internal_*). |
| `PROTECTED_FIELDS_${SITE_ID}` | Var | Optional | - | Per-site protected form fields list (e.g. PROTECTED_FIELDS_SPLITPHASE_IO). |
| `WEBHOOK_SECRET` | Secret | Optional | - | Secret key used for HMAC-SHA256 payload signing and temporary signed R2 download tokens. |
| `WEBHOOK_SECRET_${SITE_ID}` | Secret | Optional | - | Per-site webhook HMAC secret override. |
| `CF_ACCESS_ENABLED` | Var | Optional | `false` | Enable Cloudflare Zero Trust authentication enforcement on admin and file endpoints (true / false). |
| `CF_ACCESS_TEAM_DOMAIN` | Var | Optional | - | Cloudflare Access team domain for JWKS certificate verification (e.g. myteam.cloudflareaccess.com). |
| `CF_ACCESS_TEAM_DOMAIN_${SITE_ID}` | Var | Optional | - | Per-site Cloudflare Access team domain override. |
| `CF_ACCESS_AUD` | Secret | Optional | - | Expected Cloudflare Access Application Audience (AUD) tag. |
| `CF_ACCESS_AUD_${SITE_ID}` | Secret | Optional | - | Per-site Cloudflare Access Application Audience (AUD) tag override. |
| `SIGNED_URL_TTL_SECONDS` | Var | Optional | `900` | Expiration time in seconds for temporary signed R2 download URLs included in webhooks (e.g. 900 for 15 minutes). |
| `MAX_FILE_SIZE_MB` | Var | Optional | `10` | Maximum allowed file upload size in megabytes for form attachments. |

<!-- CONFIG_TABLE_END -->

### Configuration Storage Rules

1. **`.dev.vars` (Git Ignored)**: Recommended for local dev and local deployment overrides (`ALLOWED_ORIGINS`, `EMAIL_PROVIDER`, `EMAIL_TO`).
2. **Wrangler KMS Secrets (`npx wrangler secret put`)**: Required for sensitive secrets (`TURNSTILE_SECRET_KEY_*`, `EMAIL_API_KEY`, `API_KEY`).
3. **`wrangler.toml`**: Public open-source template defaults only. Never put private email addresses or API keys in `wrangler.toml`.

## Step 10: Set Up Authentication for Admin Endpoints

The `/submissions/:formId` and `/submission/:id` endpoints require authentication.

1. Generate an API key:
```bash
openssl rand -hex 32
```

2. Store it as a secret:
```bash
wrangler secret put API_KEY
# Paste the generated key when prompted
```

3. Use it in your requests:
```bash
curl -H "Authorization: Bearer your-api-key" \
  https://your-worker.workers.dev/submissions/contact-form
```

## Step 11: Configure Webhooks (Optional)

You can configure FreeFormer to send a JSON POST request to a webhook URL whenever a form is submitted successfully.

1. Set the webhook URL:
```bash
wrangler secret put WEBHOOK_URL
# Enter your webhook URL when prompted
```

The webhook payload will look like this:
```json
{
  "id": "submission-id",
  "formId": "contact-form",
  "data": { ... },
  "metadata": { ... },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

Headers included:
- `X-FreeFormer-Event`: `submission`
- `X-FreeFormer-Signature`: Your `API_KEY` (if configured)

## Testing Your Setup

### Test Form Submission

```bash
curl -X POST https://your-worker.workers.dev/submit \
  -H "Content-Type: application/json" \
  -d '{
    "formId": "test-form",
    "turnstileToken": "test-token",
    "data": {
      "name": "Test User",
      "email": "test@example.com",
      "message": "This is a test"
    }
  }'
```

Note: This will fail Turnstile verification unless you use a real token from the widget.

### View Submissions

```bash
curl -H "Authorization: Bearer your-api-key" \
  https://your-worker.workers.dev/submissions/test-form
```

### Test Email Configuration

You can test your email settings without submitting a form using the `/email-test` endpoint. This requires your API key.

```bash
curl -X POST https://your-worker.workers.dev/email-test \
  -H "Authorization: Bearer your-api-key"
```

If successful, you will receive a response like:
```json
{
  "success": true,
  "message": "Test email sent successfully",
  "provider": "resend"
}
```
And check the configured email inbox for the test message.

## Pre-Commit Quality Gate & Security Scanner

FreeFormer includes an automated pre-commit quality gate (`npm run pre-commit` / `bash scripts/scan-secrets.sh`) that verifies staged files before committing:

1. **Documentation & Manifest Sync (`npm run check-docs`)**: Verifies that the Environment Variables table above matches `config-manifest.json` exactly. Run `npm run sync-docs` to re-sync if drifted.
2. **Private Configuration Files**: Prevents accidental staging of `.dev.vars`, `wrangler.overrides.toml`, or `wrangler.local.toml`.
3. **Hardcoded Secrets Scanner**: Detects leaked API keys, Turnstile secret tokens, or private credentials in staged diffs.
4. **Public `wrangler.toml` Sanitization**: Ensures `wrangler.toml` contains no personal email addresses or custom domain route patterns.

```bash
# Run the pre-commit quality gate manually
npm run pre-commit
```

## Post-Deployment Verification & Key Cross-Referencing

After deploying to Cloudflare (`npm run deploy:prod` / `npx wrangler deploy -c wrangler.overrides.toml`), FreeFormer automatically runs `scripts/verify-deploy.js` to execute live health checks:

1. **Live Binding Diagnostics (`GET /`)**: Queries the deployed Worker to verify that KV/D1 storage is active, Turnstile secrets are configured, and email providers are recognized.
2. **Local vs. Remote Key Cross-Referencing**:
   - Parses local `.dev.vars` and `wrangler.overrides.toml` to extract all tested configuration keys (`TURNSTILE_SECRET_KEY_${SITE_ID}`, `EMAIL_TO_${SITE_ID}`, `WEBHOOK_URL_${SITE_ID}`, etc.).
   - Cross-references them against the remote Worker's active secret list (`configuredKeys`).
   - If any variable or secret tested locally was not provisioned in Cloudflare, it outputs a warning with the exact `npx wrangler secret put KEY_NAME` command needed.

```bash
# Run post-deployment verification manually at any time
npm run verify-deploy
```

## Troubleshooting

### "Turnstile verification failed"
- Make sure you're using the correct secret key
- Verify the token is fresh (tokens expire after a few minutes)
- Check that the domain matches your Turnstile configuration

### "Rate limit exceeded"
- Wait for the rate limit window to expire
- Adjust `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW` in `wrangler.toml`

### "No storage backend configured"
- Make sure you've uncommented and configured either KV or D1 in `wrangler.toml`
- Run `wrangler dev` to see if there are any binding errors

### CORS errors
- Add your domain to `ALLOWED_ORIGINS` in `wrangler.toml`
- Make sure you're using HTTPS in production

## Next Steps

- Set up email notifications for new submissions
- Create an admin dashboard to view submissions
- Implement custom validation rules
- Add file upload support

## Support

For issues and questions, please check the README.md file or create an issue in your repository.

# FreeFormer Outbound Delivery Guide: Emails & Webhooks 📧🔗

This guide covers configuring email notifications and real-time outbound webhooks for form submissions.

---

## 1. Email Notifications

FreeFormer supports multiple outbound email providers configured via environment variables and Cloudflare KMS secrets.

### Supported Providers (`EMAIL_PROVIDER`)

| Provider | `EMAIL_PROVIDER` | Required Credentials | Notes |
| :--- | :--- | :--- | :--- |
| **Mailtrap** *(Default)* | `mailtrap` | `EMAIL_API_KEY`, `EMAIL_TO` | High deliverability transactional email API. |
| **Resend** | `resend` | `EMAIL_API_KEY`, `EMAIL_TO` | Modern developer email API. |
| **SendGrid** | `sendgrid` | `EMAIL_API_KEY`, `EMAIL_TO` | Twilio SendGrid v3 Mail Send API. |
| **Mailgun** | `mailgun` | `EMAIL_API_KEY`, `EMAIL_TO`, `MAILGUN_DOMAIN` | Mailgun Messages API. |
| **Zoho CPaaS** | `zoho` (or `zoho_cpaas`, `zeptomail`) | `EMAIL_API_KEY`, `EMAIL_FROM`, `EMAIL_TO` | Zoho CPaaS / ZeptoMail email API (`https://cpaas.zoho.com/v1.1/email`). Optional `ZOHO_API_URL` override for regional or ZeptoMail domains. Send Mail Token is passed via `Authorization: Zoho-enczapikey <token>`. |
| **Console Logger** | `console` | None | Prints formatted submission tables to Worker stdout (`wrangler tail`). |
| **Disabled** | `none` | None | Skips email dispatching entirely. |

### Global vs. Per-Site Multi-Tenant Email Routing

FreeFormer allows you to configure global fallback email settings as well as site-specific recipient and sender overrides using `siteId`:

* **Global Defaults**: `EMAIL_TO`, `EMAIL_FROM`, `EMAIL_PROVIDER`
* **Per-Site Overrides**: `EMAIL_TO_${SITE_ID}`, `EMAIL_FROM_${SITE_ID}`, `EMAIL_PROVIDER_${SITE_ID}` (e.g. `EMAIL_TO_MYSITE_A=team-a@example.com`, `EMAIL_TO_MYSITE_B=team-b@example.com`).

```toml
# Example wrangler.overrides.toml with per-site email targets
[vars]
EMAIL_PROVIDER = "mailtrap"
EMAIL_TO = "default-alerts@example.com"
EMAIL_TO_BRAINENDEAVOR = "brian@brainendeavor.com"
EMAIL_TO_SPLITPHASE = "brian@splitphase.com"
```

Set your provider API key as a secure secret:
```bash
npx wrangler secret put EMAIL_API_KEY
```

---

## 2. Mustache Email Templates

Email templates are logic-less Mustache files located in `src/templates/`:

* **HTML Template**: [`src/templates/email.html.mustache`](file:///Users/bmo/code/websites/freeformer/src/templates/email.html.mustache)
* **Plaintext Fallback**: [`src/templates/email.text.mustache`](file:///Users/bmo/code/websites/freeformer/src/templates/email.text.mustache)

### System Token Filtering
FreeFormer automatically sanitizes system tokens (`cf-turnstile-response`, `turnstileToken`, `formId`, `siteId`) so only actual user form input data appears in the `{{#fields}}` template loop.

### Template Variables Reference

| Variable | Description | Example |
| :--- | :--- | :--- |
| `{{formId}}` | Identifier of submitted form | `contact-form` |
| `{{submissionId}}` | Unique ID of submission | `sub_9a8b7c6d5e` |
| `{{timestamp}}` | UTC submission timestamp | `Tue, 19 Aug 2026 10:00:00 GMT` |
| `{{ip}}` | Client IP address | `192.168.1.1` |
| `{{#turnstileScore}}...{{/turnstileScore}}` | Conditional Turnstile spam score | `0.95` |
| `{{#fields}} {{key}} : {{value}} {{/fields}}` | Sanitized array of user submission fields | `[ { key: "name", value: "Jane" } ]` |

### Protected Form Fields (Email Security)

Because email messages are transmitted across public mail relays and stored in plaintext inboxes, sensitive or noisy data should not be sent via email. 

Fields defined in `PROTECTED_FIELDS` (or per-site `PROTECTED_FIELDS_${SITE_ID}`, or HTML `data-freeformer-protected-fields="ssn,tax_id,utm_*"`) are **omitted from notification emails** while remaining **100% securely preserved in encrypted D1/KV storage** and webhook payloads.

### Spam Quarantine & Instant Alert Suppression

When incoming submissions score at or above `SPAM_THRESHOLD` (default: `60`):
* **Immediate Email Suppression**: FreeFormer automatically suppresses instant email notification alerts to your inbox.
* **Safe Persistence**: Submissions are safely saved to D1 or KV storage with full spam audit telemetry (`metadata.isSpam = true`, `metadata.spamScore`, `metadata.spam.reasons`, and `metadata.spam.metrics`).
* **Zero Lost Leads**: False positives can be inspected in the FreeFormer Zero-Trust Admin dashboard (`/admin?filter=spam`).

---

## 3. Periodic Spam Digest (Zero-Noise Summaries)

Rather than sending noisy alerts for spam messages as they arrive, FreeFormer aggregates quarantined submissions and delivers a single **Weekly Spam Digest**:

* **Zero-Noise Guarantee**: If no spam was detected during the period (`spamCount === 0`), **no email is sent**.
* **Automated Cron Trigger**: Runs on a Cloudflare Workers cron schedule (`[triggers] crons = ["0 9 * * 1"]` for every Monday at 09:00 UTC).
* **Digest Content**:
  - High-level metric cards (Quarantined Spam count, Clean Forwarded count, Spam percentage).
  - Summary table of all quarantined submissions with Sender, Site, Form, Spam Score, Top Reason, and Message snippet.
  - Direct deep link to FreeFormer Admin UI (`/admin?filter=spam`).
* **Configuration**:
  - `SPAM_DIGEST_ENABLED`: Toggle digests (`"true"` / `"false"`).
  - `SPAM_DIGEST_EMAIL_TO`: Specific recipient email for digests (falls back to `EMAIL_TO`).
  - `POST /admin/spam-digest?dryRun=true`: Preview or trigger the digest on demand from curl or admin tools.

---

## 4. Outbound Universal Webhooks (Zapier, Make, n8n, Custom APIs)

FreeFormer dispatches standardized, battle-tested webhook payloads upon every successful form submission. This envelope format is natively compatible with **Webhooks by Zapier (Catch Hooks)**, **Make (Integromat)**, **n8n**, Slack, and custom backend APIs.

### Webhook Configuration

* **Global Fallback**: Set `WEBHOOK_URL` in `wrangler.overrides.toml` or `npx wrangler secret put WEBHOOK_URL`.
* **Per-Site Webhook**: Set `WEBHOOK_URL_${SITE_ID}` (e.g. `WEBHOOK_URL_SPLITPHASE_IO`).
* **HMAC Signature Secret**: Set `WEBHOOK_SECRET` (or `WEBHOOK_SECRET_${SITE_ID}`).

### Webhook Payload Format

```json
{
  "event": "form_submission",
  "id": "sub_9a8b7c6d5e",
  "formId": "contact",
  "siteId": "splitphase.io",
  "timestamp": "2026-09-04T10:00:00.000Z",
  "data": {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "message": "Hello from FreeFormer!"
  },
  "attachments": [
    {
      "filename": "requirements.pdf",
      "size": 1048576,
      "mimeType": "application/pdf",
      "downloadUrl": "https://forms.splitphase.io/files/signed?key=...&token=...&expires=1788456000"
    }
  ],
  "metadata": {
    "ip": "203.0.113.195",
    "userAgent": "Mozilla/5.0...",
    "turnstileScore": 1.0
  }
}
```

### Temporary Signed R2 Download URLs for Automation
Because FreeFormer's Cloudflare R2 bucket is private and guarded by Cloudflare Zero Trust, third-party webhook processors (like Zapier) cannot log in interactively. FreeFormer automatically generates a short-lived HMAC-SHA256 signed download URL (`/files/signed?key=...&token=...&expires=...`, default TTL: 15 minutes) for each attachment, allowing Zapier or Make to upload files to Google Drive, Dropbox, or a CRM.

### Webhook HTTP Headers
* `Content-Type: application/json`
* `X-FreeFormer-Event: form_submission`
* `X-FreeFormer-Timestamp: <unix_timestamp>`
* `X-FreeFormer-Signature: sha256=<hex_hmac>` *(Included when `WEBHOOK_SECRET` or `API_KEY` is configured)*

### Webhook Testing (`POST /webhook-test`)
Trigger a test event to verify your Zapier Catch Hook or webhook integration without submitting live forms:
```http
POST /webhook-test HTTP/1.1
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "siteId": "splitphase.io",
  "webhookUrl": "https://hooks.zapier.com/hooks/catch/12345/abcdef/"
}
```


# FreeFormer Client Integration Guide 💻

This guide covers integrating FreeFormer with your frontend websites—from zero-config static HTML forms to single-page applications (React, Vue, Svelte, Astro).

---

## 1. Quick Integration: Vanilla HTML & Fetch

The simplest way to submit a form to FreeFormer without external dependencies:

```html
<!-- 1. Include Cloudflare Turnstile API -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<!-- 2. Form with Turnstile Widget -->
<form
  id="contact-form"
  action="https://your-worker.workers.dev/submit"
  method="POST"
  data-freeformer="contact"
  data-freeformer-site="splitphase.io"
>
  <input type="text" name="name" placeholder="Your Name" required />
  <input type="email" name="email" placeholder="Your Email" required />
  <textarea name="message" placeholder="Your Message" required></textarea>

  <!-- Turnstile Anti-Spam Widget -->
  <div class="cf-turnstile" data-sitekey="YOUR_TURNSTILE_SITE_KEY"></div>

  <button type="submit">Send Message</button>
</form>

<!-- 3. Lightweight AJAX Submission Handler -->
<script>
  const form = document.getElementById('contact-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = turnstile.getResponse();

    if (!token) {
      alert('Please complete the anti-spam verification.');
      return;
    }

    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    delete data['cf-turnstile-response']; // Keep payload clean

    // Auto-extract domain if data-freeformer-site is omitted
    const siteId = form.dataset.freeformerSite || window.location.hostname.replace(/^www\./i, '');

    try {
      const res = await fetch(form.action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          formId: form.dataset.freeformer || 'contact',
          siteId: siteId,
          turnstileToken: token,
          data,
        }),
      });

      const result = await res.json();
      if (result.success) {
        alert('Message sent successfully!');
        form.reset();
        turnstile.reset();
      } else {
        alert('Error: ' + (result.error || 'Failed to submit'));
        turnstile.reset();
      }
    } catch (err) {
      alert('Network error. Please try again.');
      turnstile.reset();
    }
  });
</script>
```

---

## 2. Using the FreeFormer Client Library (`/form-handler.js`)

FreeFormer serves a lightweight (under 2KB) drop-in client library directly from your Worker.

### Option A: Automatic Initialization via HTML Data Attributes

Simply tag any form with `data-freeformer`, and the library automatically handles Turnstile token extraction, submission lifecycle, and UI feedback states:

```html
<!-- Include Turnstile and FreeFormer scripts -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script src="https://your-worker.workers.dev/form-handler.js"></script>

<form
  action="https://your-worker.workers.dev/submit"
  method="POST"
  data-freeformer="contact-form"
  data-freeformer-site="splitphase.io"
>
  <input type="text" name="name" placeholder="Your Name" required />
  <input type="email" name="email" placeholder="Your Email" required />
  <textarea name="message" placeholder="Your Message" required></textarea>

  <div class="cf-turnstile" data-sitekey="YOUR_TURNSTILE_SITE_KEY"></div>
  <button type="submit">Send Message</button>
</form>
```

### Option B: Programmatic Initialization via JavaScript

```javascript
FreeFormer.init({
  workerUrl: 'https://your-worker.workers.dev',
  siteId: 'splitphase.io', // Optional: defaults to window.location.hostname
  turnstileSiteKey: 'YOUR_TURNSTILE_SITE_KEY', // Automatically creates Turnstile widget if omitted in HTML
  autoInit: true,
  debug: false
});

// Listen for custom lifecycle events
const form = document.getElementById('contact-form');

form.addEventListener('freeformer:success', (e) => {
  console.log('Submission ID:', e.detail.submissionId);
  // e.g., redirect to /thank-you or trigger analytics event
});

form.addEventListener('freeformer:error', (e) => {
  console.error('Submission failed:', e.detail.error);
});
```

---

## 3. Supported Form Attributes

| Attribute | Description | Example |
| :--- | :--- | :--- |
| `data-freeformer` | Unique form identifier *(Required)* | `data-freeformer="contact-form"` |
| `data-freeformer-site` | Site ID or domain name. If omitted, automatically extracts current webpage hostname. | `data-freeformer-site="splitphase.io"` |
| `data-freeformer-protected-fields` | Comma-separated list of field names/patterns omitted from email notifications (persisted in DB) | `data-freeformer-protected-fields="ssn,tax_id,utm_*"` |
| `data-success-message` | Custom success message displayed above form | `data-success-message="Thank you! We'll reply shortly."` |
| `data-redirect` | Optional URL redirect upon successful submission | `data-redirect="/thank-you"` |

### File Attachments & Uploads

FreeFormer natively supports file uploads via standard `<input type="file">` tags. Files are automatically validated (size limit default 10MB, safe MIME-types) and stored in your private Cloudflare R2 bucket:

```html
<form data-freeformer="job-application" data-freeformer-site="splitphase.io">
  <input type="text" name="name" placeholder="Full Name" required />
  <input type="email" name="email" placeholder="Email Address" required />
  <input type="file" name="resume" accept=".pdf,.doc,.docx" required />
  <button type="submit">Submit Application</button>
</form>
```
Uploaded files are stored with namespaced keys and can only be accessed by authenticated staff via **Cloudflare Zero Trust** or automated webhook signed links.


---

## 4. Multi-Tenant Architecture & Domain Resolution

FreeFormer is designed to power multiple separate websites from a single Worker deployment with zero cross-talk.

### 1. Automatic Domain Extraction (Zero-Config)
* **Client-Side**: If `data-freeformer-site` is omitted, the client library automatically uses `window.location.hostname.replace(/^www\./i, '')` (e.g. `splitphase.io`).
* **Server-Side**: If a direct submission omits `siteId`, the server extracts the domain from the HTTP `Origin` or `Referer` headers.

### 2. Smart Secret & Variable Resolution
When a form submits under a domain (e.g. `siteId = "splitphase.io"`), FreeFormer automatically searches for secrets and routing variables using normalized fallbacks:

```text
siteId: "splitphase.io"
  1. Exact with underscores:  TURNSTILE_SECRET_KEY_SPLITPHASE_IO
  2. Alphanumeric only:       TURNSTILE_SECRET_KEY_SPLITPHASEIO
  3. Base domain prefix:      TURNSTILE_SECRET_KEY_SPLITPHASE
  4. Global fallback:         TURNSTILE_SECRET_KEY
```

This resolution order applies to:
* **Turnstile Anti-Spam**: `TURNSTILE_SECRET_KEY_${SITE_ID}` $\rightarrow$ `TURNSTILE_SECRET_KEY`
* **Email Recipient**: `EMAIL_TO_${SITE_ID}` $\rightarrow$ `EMAIL_TO`
* **Email Sender**: `EMAIL_FROM_${SITE_ID}` $\rightarrow$ `EMAIL_FROM`
* **Email Provider**: `EMAIL_PROVIDER_${SITE_ID}` $\rightarrow$ `EMAIL_PROVIDER`
* **Email API Key**: `EMAIL_API_KEY_${SITE_ID}` $\rightarrow$ `EMAIL_API_KEY`
* **Webhooks**: `WEBHOOK_URL_${SITE_ID}` $\rightarrow$ `WEBHOOK_URL`

### 3. Separation of Form Data vs. System Metadata
* **System Metadata** (`formId`, `siteId`, `turnstileToken`) must always be specified via `<form>` dataset attributes (`data-freeformer`, `data-freeformer-site`) or JS configuration—**never via hidden HTML `<input>` tags**.
* **Form Payload Data**: Hidden HTML `<input>` tags inside forms are strictly preserved for user and business form payload data.

---

## 5. Setting Up Honeypot Traps (Edge Spam Protection)

FreeFormer's edge spam engine evaluates submissions for hidden **honeypot fields** (configured via `SPAM_HONEYPOT_FIELDS`, default: `_hp,website,company_url`). 

Automated bots crawl HTML forms and blindly fill every input they find. Legitimate human visitors never see or interact with hidden honeypot fields. When a honeypot field is populated, FreeFormer automatically applies a **+80 point spam penalty**, quarantining the submission in storage and suppressing instant notification emails.

### Adding a Honeypot to Your HTML Form

Add an input named `_hp` or `website` styled offscreen or hidden:

```html
<form data-freeformer="contact" data-freeformer-site="splitphase.io">
  <!-- Legitimate fields -->
  <input type="text" name="name" placeholder="Your Name" required />
  <input type="email" name="email" placeholder="Your Email" required />
  <textarea name="message" placeholder="Your Message" required></textarea>

  <!-- Honeypot trap (Hidden from humans, visible to bots) -->
  <div style="position: absolute; left: -9999px; opacity: 0; pointer-events: none;" aria-hidden="true">
    <label for="form_website_hp">Leave this field blank</label>
    <input type="text" id="form_website_hp" name="_hp" tabindex="-1" autocomplete="off" />
  </div>

  <button type="submit">Send Message</button>
</form>
```


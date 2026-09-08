/**
 * FreeFormer Zero-Trust Admin UI
 * Zero-build, server-rendered administration dashboard powered by hono/html.
 * Allows authenticated staff to browse submissions, inspect protected fields,
 * view metadata/Turnstile scores, and preview/download R2 attachments.
 */

import { Hono } from 'hono';
import { html } from 'hono/html';
import type { AuthenticatedUser } from '../auth';
import { getSubmissions, getSubmission, type StoredSubmission } from '../storage';
import { isFieldProtected } from '../templates';
import { resolveSiteEnv } from '../index';

type AdminBindings = {
  KV?: KVNamespace;
  DB?: D1Database;
  ATTACHMENTS?: R2Bucket;
  STORAGE_ENGINE?: string;
  PROTECTED_FIELDS?: string;
  [key: string]: any;
};

type AdminVariables = {
  user: AuthenticatedUser;
};

export const adminApp = new Hono<{ Bindings: AdminBindings; Variables: AdminVariables }>();

// Base layout with responsive dark-mode styling
function adminLayout(title: string, user: AuthenticatedUser, content: any) {
  return html`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} • FreeFormer Admin</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --badge-bg: #312e81;
      --badge-text: #c7d2fe;
      --protected-bg: #701a75;
      --protected-text: #f5d0fe;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 0 0 40px 0;
    }
    header {
      background: var(--card-bg);
      border-bottom: 1px solid var(--card-border);
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
      text-decoration: none;
    }
    .user-pill {
      background: #0f172a;
      border: 1px solid var(--card-border);
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 13px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
    }
    main {
      max-width: 1200px;
      margin: 24px auto;
      padding: 0 20px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .filter-bar {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 20px;
    }
    input, select {
      background: #0f172a;
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 14px;
    }
    input:focus, select:focus {
      outline: 2px solid var(--primary);
    }
    .btn {
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn-secondary {
      background: #334155;
      color: #cbd5e1;
    }
    .btn-secondary:hover { background: #475569; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--card-border);
    }
    th {
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 500;
      background: var(--badge-bg);
      color: var(--badge-text);
    }
    .badge-protected {
      background: var(--protected-bg);
      color: var(--protected-text);
    }
    .badge-success { background: #064e3b; color: #a7f3d0; }
    .badge-warning { background: #78350f; color: #fde68a; }
    .badge-danger { background: #7f1d1d; color: #fecaca; }
    .grid-2 {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
    }
    @media (max-width: 800px) {
      .grid-2 { grid-template-columns: 1fr; }
    }
    pre {
      background: #090d16;
      border: 1px solid var(--card-border);
      padding: 14px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 13px;
      color: #38bdf8;
    }
  </style>
</head>
<body>
  <header>
    <a href="/admin" class="brand">
      <span>⚡</span> FreeFormer Admin
    </a>
    <div class="user-pill">
      <span class="status-dot"></span>
      <span>${user.email}</span>
      <span style="font-size: 11px; color: #64748b;">(${user.authMethod})</span>
    </div>
  </header>
  <main>
    ${content}
  </main>
</body>
</html>`;
}

// 1. Submissions List View
adminApp.get('/', async (c) => {
  const user = c.get('user');
  const siteId = c.req.query('siteId') || '';
  const formId = c.req.query('formId') || '';
  const limit = parseInt(c.req.query('limit') || '50', 10);
  const offset = parseInt(c.req.query('offset') || '0', 10);

  const storageEngine = (c.env.STORAGE_ENGINE || (c.env.DB ? 'd1' : 'kv')).toLowerCase();
  const submissions = await getSubmissions(
    storageEngine === 'kv' ? c.env.KV : undefined,
    storageEngine === 'd1' ? c.env.DB : undefined,
    formId,
    siteId,
    limit,
    offset
  );

  const content = html`
    <div class="card">
      <h2 style="margin-top:0; font-size: 20px;">Form Submissions</h2>
      <form method="GET" action="/admin" class="filter-bar">
        <input type="text" name="siteId" placeholder="Filter by Site ID..." value="${siteId}">
        <input type="text" name="formId" placeholder="Filter by Form ID..." value="${formId}">
        <button type="submit" class="btn">Filter</button>
        ${siteId || formId ? html`<a href="/admin" class="btn btn-secondary">Clear</a>` : ''}
      </form>

      ${submissions.length === 0
        ? html`<p style="color: var(--text-muted); text-align: center; padding: 40px 0;">No submissions found.</p>`
        : html`
          <table>
            <thead>
              <tr>
                <th>Date / Time</th>
                <th>Site ID</th>
                <th>Form ID</th>
                <th>Primary Info</th>
                <th>Attachments</th>
                <th>Score</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${submissions.map((sub: StoredSubmission) => {
                const date = new Date(sub.metadata?.timestamp || Date.now()).toLocaleString();
                const primaryName = sub.data?.name || sub.data?.fullName || sub.data?.contact_name || '';
                const primaryEmail = sub.data?.email || sub.data?.email_address || '';
                const primary = [primaryName, primaryEmail].filter(Boolean).join(' • ') || '(No contact info)';
                const attCount = sub.attachments?.length || 0;
                const score = sub.metadata?.turnstileScore;

                return html`
                  <tr>
                    <td style="white-space: nowrap; color: var(--text-muted);">${date}</td>
                    <td><span class="badge">${sub.siteId}</span></td>
                    <td><code>${sub.formId}</code></td>
                    <td><strong>${primary}</strong></td>
                    <td>
                      ${attCount > 0
                        ? html`<span class="badge" style="background:#0369a1; color:#bae6fd;">📎 ${attCount} file${attCount > 1 ? 's' : ''}</span>`
                        : html`<span style="color:#64748b;">None</span>`}
                    </td>
                    <td>
                      ${score !== undefined
                        ? html`<span class="badge ${score >= 0.7 ? 'badge-success' : score >= 0.4 ? 'badge-warning' : 'badge-danger'}">${score.toFixed(2)}</span>`
                        : html`<span style="color:#64748b;">-</span>`}
                    </td>
                    <td>
                      <a href="/admin/submissions/${sub.id}?siteId=${encodeURIComponent(sub.siteId)}&formId=${encodeURIComponent(sub.formId)}" class="btn" style="padding: 4px 10px; font-size: 12px;">View</a>
                    </td>
                  </tr>
                `;
              })}
            </tbody>
          </table>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px;">
            <span style="font-size: 13px; color: var(--text-muted);">
              Showing ${submissions.length} submission(s)
            </span>
            <div style="display: flex; gap: 8px;">
              ${offset > 0
                ? html`<a href="/admin?siteId=${encodeURIComponent(siteId)}&formId=${encodeURIComponent(formId)}&offset=${Math.max(0, offset - limit)}&limit=${limit}" class="btn btn-secondary">Previous</a>`
                : ''}
              ${submissions.length === limit
                ? html`<a href="/admin?siteId=${encodeURIComponent(siteId)}&formId=${encodeURIComponent(formId)}&offset=${offset + limit}&limit=${limit}" class="btn btn-secondary">Next</a>`
                : ''}
            </div>
          </div>
        `}
    </div>
  `;

  return c.html(adminLayout('Submissions', user, content));
});

// 2. Submission Detail Inspector
adminApp.get('/submissions/:id', async (c) => {
  const user = c.get('user');
  const id = c.req.param('id');
  const siteId = c.req.query('siteId');
  const formId = c.req.query('formId');

  const storageEngine = (c.env.STORAGE_ENGINE || (c.env.DB ? 'd1' : 'kv')).toLowerCase();
  const sub = await getSubmission(
    storageEngine === 'kv' ? c.env.KV : undefined,
    storageEngine === 'd1' ? c.env.DB : undefined,
    id,
    siteId,
    formId
  );

  if (!sub) {
    return c.html(
      adminLayout(
        'Submission Not Found',
        user,
        html`
          <div class="card" style="text-align: center; padding: 40px 20px;">
            <h2 style="color: var(--danger);">Submission Not Found</h2>
            <p style="color: var(--text-muted);">Could not find a submission with ID <code>${id}</code>.</p>
            <a href="/admin" class="btn">Return to Submissions</a>
          </div>
        `
      ),
      404
    );
  }

  // Resolve protected fields for this site to highlight protected data
  const envRecord = c.env as Record<string, string | undefined>;
  const rawProtected = resolveSiteEnv(envRecord, 'PROTECTED_FIELDS', sub.siteId) ||
    resolveSiteEnv(envRecord, 'EMAIL_PROTECTED_FIELDS', sub.siteId) ||
    resolveSiteEnv(envRecord, 'SENSITIVE_FIELDS', sub.siteId) || '';
  const protectedPatterns = rawProtected.split(',').map((s) => s.trim()).filter(Boolean);

  const entries = Object.entries(sub.data || {});
  const attachments = sub.attachments || [];

  const content = html`
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
      <div>
        <a href="/admin" style="color: var(--text-muted); text-decoration: none; font-size: 13px;">← Back to Submissions</a>
        <h1 style="margin: 4px 0 0 0; font-size: 22px;">Submission <code>${sub.id}</code></h1>
      </div>
      <span class="badge" style="font-size: 14px; padding: 6px 12px;">${sub.siteId}</span>
    </div>

    <div class="grid-2">
      <!-- Left Column: Form Payload -->
      <div>
        <div class="card">
          <h3 style="margin-top: 0; font-size: 16px;">Submitted Form Data</h3>
          <table>
            <thead>
              <tr>
                <th style="width: 35%;">Field</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              ${entries.map(([key, val]) => {
                const isProtected = isFieldProtected(key, protectedPatterns);
                const displayVal = typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val);
                return html`
                  <tr>
                    <td>
                      <div style="font-weight: 600;">${key}</div>
                      ${isProtected
                        ? html`<span class="badge badge-protected" title="This field was stripped from notification emails for security">🔒 Protected from Email</span>`
                        : ''}
                    </td>
                    <td>
                      <div style="white-space: pre-wrap; word-break: break-word;">${displayVal}</div>
                    </td>
                  </tr>
                `;
              })}
            </tbody>
          </table>
        </div>

        ${attachments.length > 0
          ? html`
            <div class="card">
              <h3 style="margin-top: 0; font-size: 16px;">📎 Uploaded Attachments (${attachments.length})</h3>
              <div style="display: flex; flex-direction: column; gap: 12px;">
                ${attachments.map((att) => {
                  const sizeKb = (att.size / 1024).toFixed(1);
                  const isImage = att.mimeType.startsWith('image/');
                  return html`
                    <div style="background: #090d16; border: 1px solid var(--card-border); padding: 12px 16px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                      <div>
                        <div style="font-weight: 600; color: var(--text);">${att.filename}</div>
                        <div style="font-size: 12px; color: var(--text-muted);">${sizeKb} KB • ${att.mimeType}</div>
                      </div>
                      <a href="/files/${att.key}" target="_blank" class="btn btn-secondary" style="font-size: 12px; padding: 6px 12px;">
                        Download
                      </a>
                    </div>
                    ${isImage
                      ? html`<div style="margin-top: -6px; padding: 0 10px;"><img src="/files/${att.key}" alt="${att.filename}" style="max-height: 140px; border-radius: 6px; border: 1px solid var(--card-border); max-width: 100%;" /></div>`
                      : ''}
                  `;
                })}
              </div>
            </div>
          `
          : ''}
      </div>

      <!-- Right Column: Metadata & Security -->
      <div>
        <div class="card">
          <h3 style="margin-top: 0; font-size: 16px;">Metadata & Verification</h3>
          <p style="font-size: 13px; line-height: 1.8; margin: 0; color: var(--text-muted);">
            <strong style="color: var(--text);">Timestamp:</strong><br>
            ${new Date(sub.metadata?.timestamp || Date.now()).toUTCString()}<br><br>
            <strong style="color: var(--text);">Client IP:</strong><br>
            <code>${sub.metadata?.ip || 'Unknown'}</code><br><br>
            <strong style="color: var(--text);">Turnstile Bot Score:</strong><br>
            ${sub.metadata?.turnstileScore !== undefined
              ? html`<span class="badge ${sub.metadata.turnstileScore >= 0.7 ? 'badge-success' : 'badge-warning'}">${sub.metadata.turnstileScore.toFixed(2)}</span>`
              : html`<span>Not available</span>`}<br><br>
            <strong style="color: var(--text);">User Agent:</strong><br>
            <span style="font-size: 12px; word-break: break-all;">${sub.metadata?.userAgent || 'Unknown'}</span>
          </p>
        </div>

        <div class="card">
          <details>
            <summary style="cursor: pointer; font-size: 14px; font-weight: 600; color: var(--primary);">
              Raw JSON Payload
            </summary>
            <pre style="margin-top: 10px;">${JSON.stringify(sub, null, 2)}</pre>
          </details>
        </div>
      </div>
    </div>
  `;

  return c.html(adminLayout(`Submission ${sub.id}`, user, content));
});

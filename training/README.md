# FreeFormer Edge Spam Classification (Sys1Pop Integration)

This directory contains the training data, distillation script, and deployment workflow for the **`freeformer-spam`** edge classification model.

---

## 1. Overview & Progressive Enhancement

FreeFormer follows a progressive enhancement strategy for spam protection:

1. **Local Heuristics (Always Active, 0ms CPU overhead):**
   - FreeFormer's native heuristics analyze honeypots, disposable email domains, link density, text entropy, and known spam keywords.
   - If `score < 30`, the submission is instantly accepted.
   - If `score >= 60`, the submission is immediately rejected or quarantined.

2. **Neural Edge Decision Engine (Optional, Progressive):**
   - For ambiguous edge cases (`score >= 30 && score < 60`), FreeFormer queries **Sys1Pop** if the `SYS1POP` service binding is configured in `wrangler.toml`.
   - The edge model runs in an adjacent Cloudflare Worker isolate using quantized INT8 Candle WASM, returning:
     - `is_spam`: boolean determination
     - `spam_category`: `legitimate_inquiry`, `commercial_sales_pitch`, `seo_backlink_spam`, `crypto_phishing`, or `automated_bot_gibberish`
     - `risk_score`: 1 to 5 risk tier
   - If `env.SYS1POP` is **not configured**, FreeFormer operates entirely on its native heuristics with zero downtime or performance penalty.

---

## 2. Directory Structure

```
training/
├── README.md               # This documentation
├── spam_dataset.json       # Labeled domain examples for spam classification
└── distill_spam.py         # Bundle exporter conforming to Sys1Pop edge spec
```

---

## 3. Training & Exporting the Model Bundle

To generate the quantized edge bundle for FreeFormer:

```bash
# Export the model bundle to ./models/freeformer-spam
python3 training/distill_spam.py --data ./training/spam_dataset.json
```

This generates:
- `models/freeformer-spam/manifest.json`: Decision heads and metadata
- `models/freeformer-spam/model.safetensors`: Quantized INT8 weights
- `models/freeformer-spam/tokenizer.json`: WordPiece tokenizer
- `models/freeformer-spam/config.json`: MiniLM backbone config

The script automatically verifies that the bundle size is within the **<35 MB** edge isolate limit.

---

## 4. Deploying to Cloudflare R2 via Sys1Pop CLI

Once generated, publish the model directly to your Sys1Pop worker's R2 bucket:

```bash
npx sys1pop model push ./models/freeformer-spam --name freeformer-spam
```

You can test the deployed model in isolation:

```bash
npx sys1pop model test freeformer-spam "Urgent: Claim your 5,000 USDT crypto airdrop now"
```

---

## 5. Enabling in FreeFormer (`wrangler.toml`)

To activate edge neural triage in production, uncomment the service binding in `wrangler.toml`:

```toml
# Optional Edge AI Classification Service Binding (Sys1Pop)
[[services]]
binding = "SYS1POP"
service = "sys1pop"
```

Then deploy FreeFormer:

```bash
npx wrangler deploy
```

# Email Security Gateway with Phishing Detection

A Flask-based web app that scans a raw email (headers + body) and flags
phishing indicators using rule-based heuristics — no external API or
paid threat-intel feed required, so it runs entirely offline.

## Features / Checks performed

| # | Check | What it catches |
|---|-------|------------------|
| 1 | Sender domain mismatch | `From`, `Reply-To`, `Return-Path` pointing to different domains |
| 2 | Lookalike / typosquat domain | `paypa1.com`, `micros0ft-support.com` etc. (with homoglyph normalization) |
| 3 | Raw IP address links | `http://192.168.x.x/...` instead of a real domain |
| 4 | URL shorteners | `bit.ly`, `tinyurl.com`, etc. hiding the real destination |
| 5 | `@` trick in URLs | `http://real-looking-text@evil.com` |
| 6 | Link text vs actual href mismatch | Anchor text shows one URL, `href` points elsewhere |
| 7 | Urgency / pressure language | "verify your account", "act now", "account suspended" |
| 8 | Generic greeting | "Dear Customer" instead of your actual name |
| 9 | Suspicious attachments | `.exe`, `.scr`, `.js`, double extensions |
| 10 | Sensitive info request | Asks for password, OTP, card number, etc. |
| 11 | SPF/DKIM/DMARC header check | Reads `Authentication-Results` / `Received-SPF` if present |

Each check contributes points to a **risk score**. The final percentage
decides the verdict: **SAFE** (<25%), **SUSPICIOUS** (25–55%), **PHISHING** (>55%).

## Project structure

```
email_security_gateway/
├── app.py                  # Flask routes (web UI + JSON API)
├── detector.py              # Core detection logic (pure Python, no Flask dependency)
├── templates/index.html     # UI: paste box + results table
├── static/style.css
├── sample_emails/
│   ├── phishing_sample.eml  # Scores ~74% -> PHISHING
│   └── legit_sample.eml     # Scores ~2%  -> SAFE
├── requirements.txt
└── Procfile                 # For Render deployment (same pattern as your NTA project)
```

## Run locally

```bash
pip install -r requirements.txt
python app.py
# open http://localhost:5000
```

## Test the detector directly (no server needed)

```bash
python3 -c "
from detector import analyze_email
print(analyze_email(open('sample_emails/phishing_sample.eml').read()))
"
```

## JSON API

```bash
curl -X POST http://localhost:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"email_content": "From: a@b.com\nSubject: test\n\nHello"}'
```

## Deploy to Render (same flow as your other projects)

1. Push this folder to a new GitHub repo.
2. On Render: New → Web Service → connect the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app` (already set in `Procfile`)
5. Deploy — Render gives you a live URL.

## Extending it further (good "future scope" points for a viva)

- Real DNS-based SPF/DKIM/DMARC verification (using `dnspython`) instead of just reading headers.
- Connect to a live mailbox via IMAP to auto-scan incoming mail.
- Use a small ML classifier (e.g. Naive Bayes / SVM on TF-IDF of the body) alongside the rule engine for a hybrid score.
- Attachment sandboxing / hash lookup against known-malware hash databases.
- Browser extension that scans Gmail/Outlook web view in real time.

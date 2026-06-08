<div align="center">

# DiscordUpload-RedditV3

**A Flask web app that fetches Reddit media posts via RSS and forwards them to a Discord channel through a webhook, plus a browser UI for uploading files directly to Discord.**

[![Python](https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-backend-lightgrey?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Overview

Two tools in one Flask backend:

- **Reddit -> Discord**: fetch posts from any subreddit via the public RSS/Atom feed and forward image or video embeds to a Discord webhook, with deduplication so posts are never sent twice
- **File upload -> Discord**: a browser UI for uploading images and videos directly to a Discord channel through a webhook (no bot token required)

No Reddit API credentials are needed. All Reddit data is sourced from the public `.rss` endpoint.

---

## How Reddit Fetching Works

```
Subreddit input -> RSS/Atom fetch -> media resolution -> webhook embed -> sent_posts.json
```

1. Your subreddit input is normalised from any format (`cats`, `r/cats`, full URL) to a bare name
2. The Atom feed is fetched with retry logic (4 attempts, exponential backoff)
3. Each entry's `<content>` HTML is unescaped and scanned for image and video URLs
4. `preview.redd.it` URLs are rewritten to `i.redd.it` for full-resolution originals
5. Posts without any resolvable media (text and link posts) are skipped automatically
6. Each sent post ID is recorded in `sent_posts.json` with a timestamp; entries older than 7 days are pruned on the next run

---

## Media Priority

For each post, media is resolved in this order:

| Priority | Source |
|---|---|
| 1 | Video URL in `<content>` HTML |
| 2 | `i.redd.it` image URL in `<content>` HTML |
| 3 | `preview.redd.it` URL (rewritten to `i.redd.it`) |
| 4 | `external-preview.redd.it` URL |
| 5 | `media:thumbnail` attribute (if a real HTTP URL) |

---

## Discord Embeds

Each post is sent as a Discord embed with:

- Post title
- `[View Post](permalink)` link
- Inline image (for image posts) or `[Video Link](url)` (for video posts)
- Turquoise accent colour (`0x40E0D0`)

A 0.5s delay is added between consecutive webhook posts to avoid rate limiting.

---

## File Upload

The `/upload` endpoint accepts multi-file form posts and forwards each file to the Discord webhook as a direct attachment. Files are validated before sending:

- Allowed extensions: `png`, `jpg`, `jpeg`, `gif`, `mp4`, `webm`, `avi`, `mov`, `mkv`
- **Magic-byte check**: the file's actual contents must match a known image/video signature, not just the extension
- Maximum file size: 25 MB per file (empty files are rejected)
- The webhook URL must start with `https://discord.com/api/webhooks/`

The browser UI guards empty/oversized files client-side and shows a **per-file progress bar** as each uploads. The Reddit->Discord flow has a **Preview** step (`/preview_reddit`) that lists the posts that would be sent before you send them.

Responses carry security headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`). A `/health` endpoint returns `{"status":"ok"}` for uptime checks. Set `LOG_JSON=true` to emit structured JSON logs (requests + app events) to stdout.

---

## Rate Limiting

- `/upload`: 50 requests per minute
- `/fetch_reddit`: 30 requests per minute
- Global default: 100 requests per minute

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

Requires: `flask`, `flask-limiter`, `requests`, `python-dotenv`, `werkzeug`

### 2. Run

```bash
python backend.py
```

The server starts on `http://0.0.0.0:1432`. Open `http://localhost:1432` in your browser to access the UI.

---

## API Reference

### `POST /upload`

| Field | Type | Description |
|---|---|---|
| `webhook_url` | string | Discord webhook URL |
| `files[]` | file(s) | One or more files to upload |

### `POST /fetch_reddit`

| Field | Type | Description |
|---|---|---|
| `webhook_url` | string | Discord webhook URL |
| `subreddit_name` | string | Subreddit name, `r/name`, or full URL |
| `num_items` | integer | Number of media posts to send (max 200) |

---

## Notes

- The `.json` Reddit API endpoint was deprecated in June 2026. This tool uses only the public RSS/Atom feed, which remains accessible without credentials.
- `sent_posts.json` is created automatically on first run. If the file becomes corrupted, it is backed up to `sent_posts.json.bak` and a fresh one is started.
- Video posts receive a clickable link in the embed description rather than an inline player, as Discord webhooks do not support inline video embeds.

---

## Get the Code

Clone with git:

```bash
git clone https://github.com/drew-codes-things/DiscordUploadRedditDL.git
```

Or with the [GitHub CLI](https://cli.github.com/):

```bash
gh repo clone drew-codes-things/DiscordUploadRedditDL
```

## License

MIT - made by [Drew](https://github.com/drew-codes-things)

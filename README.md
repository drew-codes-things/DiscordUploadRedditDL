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
6. Each sent post ID is recorded in `sent_posts.json` together with the webhook's ID (never its token) and a timestamp, so a post sent to one channel can still be sent to another; entries older than 7 days are pruned on the next run

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

## Discord Relay Source

Posts can also come from the Discord relay [RedditDownloaderV4](https://github.com/drew-codes-things/RedditDownloaderV4) uses instead of RSS: its Devvit app scans a subreddit inside Reddit and posts `RELAY:` batches of media links to a Discord webhook, which this app reads back with a bot token.

```
Devvit app -> relay webhook -> relay channel -> this app -> your webhook embed -> sent_posts.json
```

1. Set up the Devvit app, webhook and bot as in RedditDownloaderV4's README (the bot needs **Message Content Intent** and Read Message History in the relay channel)
2. Add `RELAY_BOT_TOKEN`, `RELAY_CHANNEL_ID`, and optionally `RELAY_WEBHOOK_ID` (the `{id}` in the relay webhook's URL) to `.env`
3. In Reddit, run **[starbottyyay] Fetch Media to Server** on the subreddit
4. Pick **Discord relay** in the source dropdown, then preview or send as usual

Only batches posted by a webhook (and only `RELAY_WEBHOOK_ID`'s, if set) are read; the newest 500 relay messages are searched for that subreddit's posts. Relay items carry no post title, so embeds are titled `r/<subreddit> post <id>`.

After a send, any relay message whose posts have all been sent (in this run or an earlier one) is deleted from Discord, so the channel only holds what's still waiting. Previews never delete anything. Deleting needs the bot to have **Manage Messages** in the relay channel; without it, messages are just left in place. Set `DELETE_RELAY_MESSAGES=false` in `.env` to keep every message.

---

## File Upload

The `/upload` endpoint accepts multi-file form posts and forwards each file to the Discord webhook as a direct attachment. Files are validated before sending:

- Allowed extensions: `png`, `jpg`, `jpeg`, `gif`, `webp`, `mp4`, `webm`, `avi`, `mov`, `mkv`
- **Magic-byte check**: the file's actual contents must match a known image/video signature, not just the extension
- Maximum file size: 25 MB per file (empty files are rejected); request bodies over that are refused with HTTP 413 before being read
- The webhook URL must start with `https://discord.com/api/webhooks/`

The browser UI guards empty/oversized files client-side and shows a **per-file progress bar** as each uploads. Uploads that fail for a temporary reason (network drop, rate limit, or a Discord/server error) are retried once automatically after a short pause; anything still failing gets a **Retry failed** button, while files rejected for their contents are not retried. The Reddit->Discord flow has a **Preview** step (`/preview_reddit`) that lists the posts that would be sent before you send them.

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

The server listens on `127.0.0.1:1432`. Open `http://localhost:1432` in your browser and make the owner account (below) to use the UI.

### First run and sign-in

The app has its own sign-in, switched on by default (see "Other ways in" below for the alternatives). There is one
owner account and no sign-up page.

1. Start it (`python backend.py`) and open `http://localhost:1432`. With no account yet the page goes to **Set up**.
2. The app writes a one-time setup code to its log when it starts, a line like
   `no owner account yet: open /setup and enter the setup code ...`. Enter that code, a user name and a password
   (10 characters or more, twice). The code stops anyone else who reaches the page first from making the account,
   and it works once: if the owner file is ever deleted, the next visit to **Set up** writes a new code to the log.
3. After that, the page and every `POST` need a sign-in. A session lasts 30 days. **Sign out** (`/signout`) signs
   out on every device.

How it is protected:

- The password is stored as an scrypt hash in `owner.json` next to `backend.py` (mode 600, git-ignored), never in
  plain text.
- 5 wrong passwords or setup codes from one address within 15 minutes lock that address out for the rest of the 15
  minutes (`429`). Attempts sent at once are counted before they are checked, IPv6 addresses count by their `/64`
  network, and after 100 failures from everywhere within 15 minutes each address gets one try and each network
  three (IPv4 by `/24`, IPv6 by `/48`). A right password from a locked address is refused too.
- During such an attack one wrong password from a neighbour on the same provider network does not keep your new
  browser out: that takes three wrong passwords within 15 minutes from three of their addresses (IPv4) or three of
  their home lines (IPv6, where a line's whole `/56` counts as one address).
- A browser that has signed in before keeps a signed device cookie and has its own 5 tries, so a stranger who locks
  out your address (or the address of the proxy in front) cannot lock you out of that browser. During an attack from
  many networks that browser is the way in. Making a new owner account ends every device cookie of the old one.
- The session cookie is `HttpOnly`, `SameSite=Lax` and signed with the app's secret key (`SECRET_KEY`, or
  `secret_key` next to `backend.py`, made on first start, mode 600). It is `Secure` everywhere except plain `http` on
  `localhost`, `127.0.0.1` or `[::1]` (`SECURE_COOKIES=auto`). On a plain `http` address on your home network the
  browser drops a `Secure` cookie and the sign-in page says so: use https, or set `SECURE_COOKIES=false` there.
- Forget the password? Stop the app, delete `owner.json` next to `backend.py`, start it again and set up a new owner
  with the new setup code from the log.
- Signed in, the page still carries the per-start app token, so every `POST` also needs the token and this app's
  own `Origin` (below).

With the own sign-in on, `BIND_HOST=0.0.0.0` is allowed without `APP_TOKEN`; add the LAN address or the proxy's host
name to `ALLOWED_HOSTS`. Behind a reverse proxy, list the proxy's address in `TRUSTED_PROXIES` so the lockout counts
each visitor's address from `X-Forwarded-For` instead of the proxy's (the header is read only from those addresses).

Other ways in:

- `APP_TOKEN` set: no own sign-in; the page asks for that token instead and every `POST` must send it (as before).
- `ALLOW_INSECURE=true` with no `APP_TOKEN`: no sign-in at all, the page carries a per-start token, and the app
  refuses to start on anything but loopback. Only for a machine nobody else uses.

### 3. Access settings (`.env`)

| Key | Default | Description |
|---|---|---|
| `BIND_HOST` | `127.0.0.1` | Address to listen on. Use `0.0.0.0` only to reach the app from other machines; with `ALLOW_INSECURE=true` `APP_TOKEN` is then required or the app refuses to start. |
| `ALLOWED_HOSTS` | `localhost`, `127.0.0.1`, `::1` and `BIND_HOST` | Comma-separated extra host names the browser may use, e.g. the LAN IP or a proxy's domain. Requests for any other `Host` are refused, which blocks DNS-rebinding pages. |
| `APP_TOKEN` | a random token per start | Shared secret every `POST` must send in the `X-App-Token` header. When unset, the page carries the per-start token (to a signed-in owner, or to anyone with `ALLOW_INSECURE=true`). When set, it replaces the own sign-in: the page never contains it and asks for it instead. |
| `ALLOW_INSECURE` | `false` | `true` with no `APP_TOKEN`: no sign-in at all, loopback only. |
| `SECRET_KEY` | `secret_key` file next to `backend.py` | Key that signs the own sign-in's cookie; 32 bytes or more, or the app stops at start-up. |
| `SECURE_COOKIES` | `auto` | The own sign-in's cookie is `Secure` except on plain `http` to `localhost`, `127.0.0.1` or `[::1]`; `true` or `false` force it. |
| `TRUSTED_PROXIES` | _(empty)_ | Own sign-in only: addresses or private networks of a reverse proxy in front, comma separated; their `X-Forwarded-For` gives the visitor's address to the lockout. |

Every `POST` (`/upload`, `/preview_reddit`, `/fetch_reddit`) is refused with HTTP 401 without a sign-in (own sign-in), and with HTTP 403 when the token is missing or wrong, or when the browser's `Origin` is not this app's own address, so other web pages cannot drive it. `/health` stays open; `GET /` needs the sign-in when the own sign-in is on. If you put the app behind a reverse proxy, set `APP_TOKEN` and add the proxy's host name to `ALLOWED_HOSTS`.

---

## API Reference

Every `POST` needs the `X-App-Token` header (see Access settings).

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
| `source` | string | `rss` (default) or `relay` - also accepted by `POST /preview_reddit` |

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

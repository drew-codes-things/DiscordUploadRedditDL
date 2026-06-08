import html
import io
import json
import logging
import os
import re
import shutil
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from requests.exceptions import RequestException
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

REDDIT_HEADERS = {
    "User-Agent": "linux:discord-upload-reddit-v2:2.0 (by /u/drew-gnr)",
    "Accept": "application/json",
}
REDDIT_RSS_HEADERS = {
    "User-Agent": "linux:discord-upload-reddit-v2:2.0 (by /u/drew-gnr)",
    "Accept": "application/rss+xml, application/xml, text/xml",
}
MAX_REDDIT_ITEMS = 200
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
REDDIT_RSS_BASE = "https://www.reddit.com"
REDDIT_RETRY_ATTEMPTS        = 4
REDDIT_RETRY_BACKOFF_SECONDS = 1.0

WEBHOOK_POST_DELAY   = 0.5
WEBHOOK_POST_TIMEOUT = 15

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp")
VIDEO_EXTENSIONS = (".mp4", ".webm", ".mov", ".mkv", ".avi")

ATOM_NS    = "http://www.w3.org/2005/Atom"
MEDIA_NS   = "http://search.yahoo.com/mrss/"
CONTENT_NS = "http://purl.org/rss/1.0/modules/content/"

SKIP_THUMBS = {"self", "default", "nsfw", "spoiler", "image", ""}


class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO and record.msg.startswith(("Starting", "Ready", "Shutting down")):
            return f"INFO: {record.msg}"
        if record.levelno == logging.INFO and "WEBSITE" in record.msg:
            return f"WEBSITE: {record.msg.split('WEBSITE: ')[-1]}"
        if record.levelno == logging.INFO and "RESULT" in record.msg:
            return f"RESULT: {record.msg.split('RESULT: ')[-1]}"
        if record.levelno == logging.INFO and record.msg.startswith("NOTE:"):
            return record.msg
        return super().format(record)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging():
    _logger = logging.getLogger()
    _logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    if os.getenv("LOG_JSON", "false").lower() == "true":
        console_handler.setFormatter(JsonFormatter())
    else:
        console_handler.setFormatter(CustomFormatter())
    _logger.handlers.clear()
    _logger.addHandler(console_handler)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    return _logger


logger = setup_logging()

app = Flask(__name__, template_folder="website")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "webm", "avi", "mov", "mkv"}
SENT_POSTS_FILE   = "./sent_posts.json"
SENT_POSTS_BACKUP = "./sent_posts.json.bak"

limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
        and len(secure_filename(filename)) > 0
    )


def detect_media(data):
    """Return a media type from the file's magic bytes, or None if unrecognised.

    Guards against a file with an allowed extension but non-media contents
    (e.g. an HTML page renamed to .png).
    """
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return "avi"
    if data[4:8] == b"ftyp":
        return "mp4"
    if data[:4] == b"\x1aE\xdf\xa3":
        return "mkv"
    return None


def validate_webhook_url(url):
    return url.startswith("https://discord.com/api/webhooks/")


def normalize_subreddit_name(value):
    def _clean_candidate(name):
        if not name:
            return ""
        cleaned = name.strip().strip("/")
        cleaned = re.sub(r"\.json$", "", cleaned, flags=re.I)
        cleaned = cleaned.split("?")[0].split("#")[0]
        return cleaned.split("/")[0].strip()

    if not value:
        return ""
    raw = value.strip()
    if not raw:
        return ""
    if raw.lower().startswith(("reddit.com/", "www.reddit.com/", "old.reddit.com/", "m.reddit.com/")):
        raw = "https://" + raw
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        path = parsed.path.strip("/")
        match = re.search(r"(?:^|/)r/([^/]+)", path, flags=re.I)
        if match:
            return _clean_candidate(match.group(1))
        return _clean_candidate(path)
    match = re.search(r"(?:^|/)r/([^/]+)", raw, flags=re.I)
    if match:
        return _clean_candidate(match.group(1))
    if raw.lower().startswith("r/"):
        return _clean_candidate(raw[2:])
    return _clean_candidate(raw)


def _rss_get_raw(url, timeout=15):
    last_error = None
    for attempt in range(REDDIT_RETRY_ATTEMPTS):
        try:
            resp = requests.get(url, headers=REDDIT_RSS_HEADERS, timeout=timeout)
            if resp.status_code == 429:
                try:
                    retry_after = int(resp.headers.get("Retry-After", 0) or 0)
                except (TypeError, ValueError):
                    retry_after = 0
                if attempt == REDDIT_RETRY_ATTEMPTS - 1:
                    raise RequestException(f"429 Rate limited from {url}")
                wait = retry_after if retry_after > 0 else REDDIT_RETRY_BACKOFF_SECONDS * (2 ** attempt)
                time.sleep(wait)
                continue
            if 500 <= resp.status_code < 600:
                if attempt == REDDIT_RETRY_ATTEMPTS - 1:
                    resp.raise_for_status()
                time.sleep(REDDIT_RETRY_BACKOFF_SECONDS * (2 ** attempt))
                continue
            if resp.status_code == 403:
                raise RequestException(f"403 Blocked from {url}")
            resp.raise_for_status()
            return resp.content
        except RequestException as e:
            last_error = e
            if attempt == REDDIT_RETRY_ATTEMPTS - 1:
                break
            time.sleep(REDDIT_RETRY_BACKOFF_SECONDS * (2 ** attempt))
    if last_error:
        raise last_error
    raise RequestException(f"Unable to fetch RSS from {url}")


def _preview_to_original(url):
    """
    Rewrite a preview.redd.it URL to the original i.redd.it image.

    preview.redd.it URLs look like:
      https://preview.redd.it/abcdef.jpg?width=960&...&s=<hash>
    The path component (abcdef.jpg) is the same filename hosted on i.redd.it.
    Stripping the host swap and query string gives the full-resolution original.
    """
    parsed = urlparse(url)
    if "preview.redd.it" in parsed.netloc:
        return f"https://i.redd.it{parsed.path}"
    return url


def _extract_image_from_html(raw_content):
    """
    Extract the best image URL from RSS <content> HTML.

    Reddit HTML-escapes the content inside the Atom <content> element, so
    <img src="https://..."> arrives as &lt;img src=&quot;https://...&quot;&gt;
    We must unescape before running the regex.

    Preference order:
      1. i.redd.it (full-resolution Reddit-hosted image)
      2. preview.redd.it -> rewritten to i.redd.it for original quality
      3. external-preview.redd.it
      4. Any other image URL with a known extension
    """
    if not raw_content:
        return None

    unescaped = html.unescape(raw_content)

    candidates = re.findall(r'<img[^>]+src=["\'](https?://[^"\']+)["\']', unescaped, re.I)

    if not candidates:
        return None

    def _score(u):
        u_low = u.lower()
        if "i.redd.it" in u_low:
            return 3
        if "preview.redd.it" in u_low:
            return 2
        if "external-preview.redd.it" in u_low:
            return 1
        if any(u_low.split("?")[0].endswith(ext) for ext in IMAGE_EXTENSIONS):
            return 0
        return -1

    best = max(candidates, key=_score)
    if _score(best) < 0:
        return None

    best = best.replace("&amp;", "&")
    best = _preview_to_original(best)

    return best


def _extract_video_from_html(raw_content):
    """Extract a video URL from RSS content HTML if present."""
    if not raw_content:
        return None
    unescaped = html.unescape(raw_content)
    m = re.search(r'<(?:video|source)[^>]+src=["\'](https?://[^"\']+)["\']', unescaped, re.I)
    if m:
        url = m.group(1).replace("&amp;", "&")
        if any(url.lower().endswith(ext) for ext in VIDEO_EXTENSIONS) or "v.redd.it" in url:
            return url
    return None


def _find_first(parent, *tags):
    """Return the first matching child element, or None.

    ElementTree elements with no children are falsy, so `a or b` chains on
    find() results silently skip valid-but-empty elements (e.g. a <title> that
    has text but no child tags). Compare against None explicitly instead.
    """
    for tag in tags:
        el = parent.find(tag)
        if el is not None:
            return el
    return None


def _parse_atom_entry(entry):
    title_el = _find_first(entry, f"{{{ATOM_NS}}}title", "title")
    title = (title_el.text or "").strip() if title_el is not None else ""

    permalink_full = ""
    for link_el in (entry.findall(f"{{{ATOM_NS}}}link") + entry.findall("link")):
        href = link_el.get("href", "")
        rel  = link_el.get("rel", "alternate")
        if href and rel == "alternate":
            permalink_full = href
            break
    if not permalink_full:
        id_el = _find_first(entry, f"{{{ATOM_NS}}}id", "id")
        if id_el is not None and id_el.text and id_el.text.startswith("http"):
            permalink_full = id_el.text.strip()

    permalink_path = urlparse(permalink_full).path if permalink_full else ""

    post_id = ""
    m = re.search(r"/comments/([a-z0-9]+)/", permalink_path, re.I)
    if m:
        post_id = m.group(1)

    raw_content = ""
    content_el = _find_first(
        entry,
        f"{{{ATOM_NS}}}content",
        "content",
        f"{{{CONTENT_NS}}}encoded",
        "summary",
        f"{{{ATOM_NS}}}summary",
    )
    if content_el is not None:
        raw_content = (content_el.text or "").strip()

    thumb_el  = entry.find(f"{{{MEDIA_NS}}}thumbnail")
    thumbnail = thumb_el.get("url", "") if thumb_el is not None else ""

    return {
        "id":             post_id,
        "title":          title,
        "permalink_path": permalink_path,
        "permalink_full": permalink_full,
        "raw_content":    raw_content,
        "thumbnail":      thumbnail,
    }


def fetch_reddit_posts_rss(subreddit_name, limit):
    subreddit_name = normalize_subreddit_name(subreddit_name)
    if not subreddit_name:
        raise RequestException("Invalid subreddit input")

    posts = []
    after = None

    while len(posts) < limit:
        url = f"{REDDIT_RSS_BASE}/r/{quote(subreddit_name)}/.rss?limit=25"
        if after:
            url += f"&after={after}"

        raw = _rss_get_raw(url)

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            logger.error(f"XML parse error for r/{subreddit_name}: {e}")
            break

        entries = root.findall(f"{{{ATOM_NS}}}entry") or root.findall("entry")
        if not entries:
            break

        for entry in entries:
            if len(posts) >= limit:
                break
            posts.append(_parse_atom_entry(entry))

        if len(posts) < limit and len(entries) == 25:
            last_id = posts[-1]["id"]
            if last_id:
                after = f"t3_{last_id}"
            else:
                break
        else:
            break

    return posts


def resolve_rss_post_media(rss_post):
    """
    Resolve image/video for a post using only the RSS feed data.

    The unauthenticated .json endpoint is deprecated by Reddit (June 2026),
    so we rely entirely on what the Atom feed provides:
      1. Video URL in <content> HTML
      2. Image URL in <content> HTML (unescaped; preview.redd.it upgraded to i.redd.it)
      3. media:thumbnail if it is a real URL (not a placeholder string)

    Returns dict: {video_url, image_url}
    Skips selftext - caller should discard posts with no media.
    """
    raw_content = rss_post.get("raw_content", "")
    thumbnail   = rss_post.get("thumbnail", "")

    video_url = _extract_video_from_html(raw_content)
    if video_url:
        return {"video_url": video_url, "image_url": None}

    image_url = _extract_image_from_html(raw_content)
    if image_url:
        return {"video_url": None, "image_url": image_url}

    if thumbnail and thumbnail not in SKIP_THUMBS and thumbnail.startswith("http"):
        return {"video_url": None, "image_url": thumbnail}

    return {"video_url": None, "image_url": None}


def load_sent_posts():
    if not os.path.exists(SENT_POSTS_FILE):
        return {}
    try:
        with open(SENT_POSTS_FILE, "r") as f:
            data = json.load(f)
        cutoff = datetime.now() - timedelta(days=7)
        filtered = {}
        for k, v in data.items():
            try:
                if datetime.fromisoformat(v) > cutoff:
                    filtered[k] = v
            except (TypeError, ValueError):
                logger.warning(f"Skipping malformed sent-post timestamp for key '{k}'.")
        return filtered
    except json.JSONDecodeError as e:
        logger.warning(
            f"sent_posts.json is corrupted ({e}). Backing up to {SENT_POSTS_BACKUP} and starting fresh -- "
            f"posts from the last 7 days may be re-sent once."
        )
        try:
            shutil.copy2(SENT_POSTS_FILE, SENT_POSTS_BACKUP)
        except OSError as backup_err:
            logger.warning(f"Could not create backup: {backup_err}")
        return {}
    except (IOError, ValueError) as e:
        logger.error(f"Error loading sent posts: {e}")
        return {}


def save_sent_posts(sent_posts):
    temp_path = f"{SENT_POSTS_FILE}.tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(sent_posts, f, indent=4)
        os.replace(temp_path, SENT_POSTS_FILE)
    except IOError as e:
        logger.error(f"Error saving sent posts: {e}")
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass


@app.after_request
def log_request(resp):
    if os.getenv("LOG_JSON", "false").lower() == "true" and request.path != "/health":
        logger.info(f"{request.method} {request.path} {resp.status_code}")
    return resp


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'",
    )
    return resp


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "discord-upload-reddit"}), 200


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
@limiter.limit("50 per minute")
def upload_file():
    webhook_url = request.form.get("webhook_url", "").strip()
    if not webhook_url:
        return jsonify({"error": "webhook_url is required"}), 400
    if not validate_webhook_url(webhook_url):
        return jsonify({"error": "Invalid webhook URL"}), 400
    if "files[]" not in request.files:
        return jsonify({"error": "No files were uploaded"}), 400

    files = request.files.getlist("files[]")
    uploaded_files = 0
    failed_files = []

    for file in files:
        if file.filename == "":
            failed_files.append("Empty filename")
            continue
        if not allowed_file(file.filename):
            failed_files.append(file.filename)
            continue

        safe_name  = secure_filename(file.filename)
        file_bytes = file.read()

        if len(file_bytes) == 0:
            failed_files.append(f"{safe_name} (empty file)")
            continue

        if len(file_bytes) > MAX_UPLOAD_BYTES:
            failed_files.append(f"{safe_name} (exceeds 25 MB limit: {len(file_bytes) // (1024 * 1024)} MB)")
            continue

        if detect_media(file_bytes) is None:
            failed_files.append(f"{safe_name} (contents are not a recognised image/video)")
            continue

        try:
            response = requests.post(
                webhook_url,
                files={"file": (safe_name, io.BytesIO(file_bytes))},
                timeout=WEBHOOK_POST_TIMEOUT,
            )
            if response.status_code in [200, 204]:
                uploaded_files += 1
            else:
                failed_files.append(safe_name)
        except Exception:
            failed_files.append(safe_name)

    logger.info(f"RESULT: {uploaded_files}/{len(files)} files uploaded successfully")
    return jsonify(
        {
            "message": f"{uploaded_files}/{len(files)} files uploaded successfully",
            "status": "success" if uploaded_files == len(files) else "partial",
            "uploaded_count": uploaded_files,
            "total_files": len(files),
            "failed_files": failed_files,
        }
    )


@app.route("/preview_reddit", methods=["POST"])
@limiter.limit("30 per minute")
def preview_reddit():
    """Return the media posts that WOULD be sent, without sending them (preview step)."""
    subreddit_name = request.form.get("subreddit_name", "").strip()
    if not subreddit_name:
        return jsonify({"status": "error", "message": "subreddit_name is required"}), 400

    raw_num_items = request.form.get("num_items", "").strip()
    try:
        num_items = int(raw_num_items)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "num_items must be an integer"}), 400
    if num_items <= 0 or num_items > MAX_REDDIT_ITEMS:
        return jsonify({"status": "error", "message": f"num_items must be between 1 and {MAX_REDDIT_ITEMS}"}), 400

    try:
        sent_posts = load_sent_posts()
        all_posts = fetch_reddit_posts_rss(subreddit_name, num_items * 3)
        unsent = [p for p in all_posts if p.get("id") not in sent_posts]
        preview = []
        for post in unsent:
            if len(preview) >= num_items:
                break
            media = resolve_rss_post_media(post)
            if not media["video_url"] and not media["image_url"]:
                continue
            preview.append({
                "title": post.get("title", ""),
                "permalink": post.get("permalink_full", ""),
                "image_url": media["image_url"],
                "video_url": media["video_url"],
            })
        return jsonify({"status": "success", "count": len(preview), "posts": preview})
    except Exception as e:
        logger.error(f"Error previewing posts from r/{subreddit_name}: {e}")
        return jsonify({"status": "error", "message": f"Error previewing posts from r/{subreddit_name}"}), 500


@app.route("/fetch_reddit", methods=["POST"])
@limiter.limit("30 per minute")
def fetch_reddit():
    webhook_url    = request.form.get("webhook_url", "").strip()
    subreddit_name = request.form.get("subreddit_name", "").strip()

    if not webhook_url:
        return jsonify({"status": "error", "message": "webhook_url is required"}), 400
    if not subreddit_name:
        return jsonify({"status": "error", "message": "subreddit_name is required"}), 400
    if not validate_webhook_url(webhook_url):
        return jsonify({"status": "error", "message": "Invalid webhook URL"}), 400

    raw_num_items = request.form.get("num_items", "").strip()
    if not raw_num_items:
        return jsonify({"status": "error", "message": "num_items is required"}), 400
    try:
        num_items = int(raw_num_items)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "num_items must be an integer"}), 400
    if num_items <= 0:
        return jsonify({"status": "error", "message": "Number of posts must be greater than 0"}), 400
    if num_items > MAX_REDDIT_ITEMS:
        return jsonify({"status": "error", "message": f"num_items cannot exceed {MAX_REDDIT_ITEMS}. Requested: {num_items}"}), 400

    try:
        sent_posts  = load_sent_posts()
        sent_count  = 0
        skip_count  = 0
        failed_items = []

        all_posts = fetch_reddit_posts_rss(subreddit_name, num_items * 3)
        unsent    = [p for p in all_posts if p.get("id") not in sent_posts]

        for post in unsent:
            if sent_count >= num_items:
                break

            media     = resolve_rss_post_media(post)
            video_url = media["video_url"]
            image_url = media["image_url"]

            if not video_url and not image_url:
                skip_count += 1
                logger.info(f"RESULT: Skipping text/link post: {post.get('title', '')[:60]}")
                continue

            view_link   = post.get("permalink_full") or ""
            description = f"[View Post]({view_link})" if view_link else ""

            embed = {
                "title":       post.get("title", ""),
                "color":       0x40E0D0,
                "description": description,
            }

            if video_url:
                embed["description"] += f"\n\n[Video Link]({video_url})"
            else:
                embed["image"] = {"url": image_url}

            try:
                response = requests.post(
                    webhook_url,
                    json={"embeds": [embed]},
                    timeout=WEBHOOK_POST_TIMEOUT,
                )
                if response.status_code == 204:
                    post_key = post.get("id") or post.get("permalink_path") or post.get("permalink_full")
                    if post_key:
                        sent_posts[post_key] = datetime.now().isoformat()
                    sent_count += 1
                    time.sleep(WEBHOOK_POST_DELAY)
                else:
                    failed_items.append(post.get("title") or post.get("id", "<unknown-post>"))
            except RequestException:
                failed_items.append(post.get("title") or post.get("id", "<unknown-post>"))

        save_sent_posts(sent_posts)

        msg = f"Successfully sent {sent_count} Reddit posts to Discord!"
        if skip_count:
            msg += f" ({skip_count} text/link posts skipped)"
        if failed_items:
            return jsonify({"status": "partial", "message": f"Sent {sent_count} posts. Failed: {', '.join(failed_items)}"})
        return jsonify({"status": "success", "message": msg})

    except Exception as e:
        logger.error(f"Error fetching posts from r/{subreddit_name}: {e}")
        return jsonify({"status": "error", "message": f"Error fetching posts from r/{subreddit_name}"}), 500


if __name__ == "__main__":
    logger.info("NOTE: Coded by Drew")
    logger.info("Ready")
    logger.info("WEBSITE: http://localhost:1432 or http://127.0.0.1:1432")
    try:
        app.run(host="0.0.0.0", port=1432, debug=False)
    except KeyboardInterrupt:
        logger.info("Shutting down")
        sys.exit(0)

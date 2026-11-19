import json

import pytest
import responses

import backend

WEBHOOK = "https://discord.com/api/webhooks/1/abc"
FORM = {"webhook_url": WEBHOOK, "subreddit_name": "pics", "num_items": "5"}
AUTH = {backend.APP_TOKEN_HEADER: backend.APP_TOKEN}


def media_post(post_id, title, permalink_path="/r/pics/comments/abc/title/"):
    return {
        "id": post_id,
        "title": title,
        "permalink_path": permalink_path,
        "permalink_full": f"https://www.reddit.com{permalink_path}",
        "media": {"video_url": None, "image_url": "https://i.redd.it/abc.jpg"},
    }


@pytest.fixture(autouse=True)
def no_disk_or_delay(monkeypatch):
    monkeypatch.setattr(backend, "save_sent_posts", lambda posts: None)
    monkeypatch.setattr(backend, "WEBHOOK_POST_DELAY", 0)
    monkeypatch.setattr(backend, "ALLOW_INSECURE", True)


@responses.activate
def test_titles_longer_than_discord_allows_are_shortened(monkeypatch):
    monkeypatch.setattr(backend, "load_sent_posts", lambda: {})
    monkeypatch.setattr(backend, "load_reddit_posts", lambda source, name, limit: [media_post("abc", "t" * 300)])
    responses.post(WEBHOOK, status=204)
    reply = backend.app.test_client().post("/fetch_reddit", data=FORM, headers=AUTH)
    assert reply.get_json()["status"] == "success"
    sent_title = json.loads(responses.calls[0].request.body)["embeds"][0]["title"]
    assert len(sent_title) == backend.DISCORD_EMBED_TITLE_LIMIT


@responses.activate
def test_a_post_without_an_id_is_not_sent_twice(monkeypatch):
    post = media_post("", "No id", permalink_path="/r/pics/s/shortlink")
    monkeypatch.setattr(backend, "load_sent_posts", lambda: {"/r/pics/s/shortlink": "2026-01-01T00:00:00"})
    monkeypatch.setattr(backend, "load_reddit_posts", lambda source, name, limit: [post])
    responses.post(WEBHOOK, status=204)
    backend.app.test_client().post("/fetch_reddit", data=FORM, headers=AUTH)
    assert len(responses.calls) == 0

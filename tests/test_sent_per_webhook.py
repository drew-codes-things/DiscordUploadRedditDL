import pytest
import responses

import backend

FIRST = "https://discord.com/api/webhooks/111/first-token"
SECOND = "https://discord.com/api/webhooks/222/second-token"
AUTH = {backend.APP_TOKEN_HEADER: backend.APP_TOKEN}


def media_post(post_id):
    return {
        "id": post_id,
        "title": f"Post {post_id}",
        "permalink_full": f"https://www.reddit.com/r/pics/comments/{post_id}/x/",
        "media": {"video_url": None, "image_url": f"https://i.redd.it/{post_id}.jpg"},
    }


@pytest.fixture
def store(monkeypatch):
    saved = {}
    monkeypatch.setattr(backend, "load_sent_posts", lambda: dict(saved))
    monkeypatch.setattr(backend, "save_sent_posts", lambda posts: saved.update(posts))
    monkeypatch.setattr(backend, "WEBHOOK_POST_DELAY", 0)
    monkeypatch.setattr(backend, "ALLOW_INSECURE", True)
    monkeypatch.setattr(backend, "load_reddit_posts", lambda source, name, limit: [media_post("abc")])
    return saved


def send(webhook):
    form = {"webhook_url": webhook, "subreddit_name": "pics", "num_items": "1"}
    return backend.app.test_client().post("/fetch_reddit", data=form, headers=AUTH).get_json()


def preview(webhook=None):
    form = {"subreddit_name": "pics", "num_items": "1"}
    if webhook:
        form["webhook_url"] = webhook
    return backend.app.test_client().post("/preview_reddit", data=form, headers=AUTH).get_json()


@responses.activate
def test_a_post_sent_to_one_webhook_still_goes_to_another(store):
    responses.post(FIRST, status=204)
    responses.post(SECOND, status=204)
    assert send(FIRST)["message"].startswith("Successfully sent 1 ")
    assert send(SECOND)["message"].startswith("Successfully sent 1 ")
    assert send(FIRST)["message"].startswith("Successfully sent 0 ")


@responses.activate
def test_the_record_holds_the_webhook_id_but_never_its_token(store):
    responses.post(FIRST, status=204)
    send(FIRST)
    assert list(store) == ["111 abc"]
    assert not any("first-token" in key for key in store)


@responses.activate
def test_preview_is_per_webhook_when_one_is_given(store):
    responses.post(FIRST, status=204)
    send(FIRST)
    assert preview(FIRST)["count"] == 0
    assert preview(SECOND)["count"] == 1


def test_old_records_without_a_webhook_still_count_as_sent(store):
    store["abc"] = "2026-11-12T00:00:00"
    assert preview(SECOND)["count"] == 0


def test_relay_messages_finish_when_their_posts_went_to_any_webhook():
    posts = [{"id": "c", "relay_messages": {"1": frozenset({"c", "d"})}}]
    assert backend.finished_relay_messages(posts, {"111 c": "t", "abc d": "t"}) == ["1"]
    assert backend.finished_relay_messages(posts, {"111 c": "t"}) == []


def test_webhook_id_is_read_from_the_url():
    assert backend.webhook_id_from_url(FIRST) == "111"
    assert backend.webhook_id_from_url("https://discord.com/api/webhooks/") == ""

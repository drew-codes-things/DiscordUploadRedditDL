import json

import pytest
import responses

import backend

CHANNEL = "111"
MESSAGES_URL = f"{backend.DISCORD_API_BASE}/channels/{CHANNEL}/messages"


def relay_message(message_id, items):
    return {"id": message_id, "content": "RELAY:" + json.dumps(items), "webhook_id": "hook"}


def item(post_id, subreddit="pics"):
    return {"url": f"https://i.redd.it/{post_id}.jpg", "subreddit": subreddit, "postId": f"t3_{post_id}"}


@pytest.fixture(autouse=True)
def relay_settings(monkeypatch):
    monkeypatch.setattr(backend, "RELAY_BOT_TOKEN", "token")
    monkeypatch.setattr(backend, "RELAY_CHANNEL_ID", CHANNEL)
    monkeypatch.setattr(backend, "RELAY_WEBHOOK_ID", "")
    monkeypatch.setattr(backend, "DELETE_RELAY_MESSAGES", True)


@responses.activate
def test_posts_remember_which_messages_they_came_from():
    responses.get(MESSAGES_URL, json=[relay_message("2", [item("a"), item("b", "cats")]), relay_message("1", [item("c")])])
    responses.get(MESSAGES_URL, json=[])
    posts = backend.fetch_relay_posts("pics", 10)
    by_id = {post["id"]: post for post in posts}
    assert set(by_id) == {"a", "c"}
    assert by_id["a"]["relay_messages"] == {"2": frozenset({"a", "b"})}


def test_only_fully_used_messages_are_finished():
    posts = [
        {"id": "a", "relay_messages": {"2": frozenset({"a", "b"})}},
        {"id": "c", "relay_messages": {"1": frozenset({"c"})}},
    ]
    assert backend.finished_relay_messages(posts, {"a": "t", "c": "t"}) == ["1"]
    assert sorted(backend.finished_relay_messages(posts, {"a": "t", "b": "t", "c": "t"})) == ["1", "2"]


@responses.activate
def test_finished_messages_are_deleted():
    responses.delete(f"{MESSAGES_URL}/1", status=204)
    posts = [{"id": "c", "relay_messages": {"1": frozenset({"c"})}}]
    assert backend.delete_finished_relay_messages(posts, {"c": "t"}) == 1


def test_deleting_can_be_turned_off(monkeypatch):
    monkeypatch.setattr(backend, "DELETE_RELAY_MESSAGES", False)
    posts = [{"id": "c", "relay_messages": {"1": frozenset({"c"})}}]
    assert backend.delete_finished_relay_messages(posts, {"c": "t"}) == 0


@responses.activate
def test_missing_permission_stops_after_first_failure():
    responses.delete(f"{MESSAGES_URL}/1", status=403)
    posts = [{"id": "c", "relay_messages": {"1": frozenset({"c"}), "2": frozenset({"c"})}}]
    assert backend.delete_finished_relay_messages(posts, {"c": "t"}) == 0
    assert len(responses.calls) == 1


@responses.activate
def test_fetch_reddit_deletes_used_relay_messages(monkeypatch, tmp_path):
    monkeypatch.setattr(backend, "load_sent_posts", lambda: {})
    monkeypatch.setattr(backend, "save_sent_posts", lambda posts: None)
    monkeypatch.setattr(backend, "WEBHOOK_POST_DELAY", 0)
    responses.get(MESSAGES_URL, json=[relay_message("5", [item("x"), item("y")])])
    responses.get(MESSAGES_URL, json=[])
    responses.post("https://discord.com/api/webhooks/1/abc", status=204)
    responses.delete(f"{MESSAGES_URL}/5", status=204)
    client = backend.app.test_client()
    reply = client.post("/fetch_reddit", data={"webhook_url": "https://discord.com/api/webhooks/1/abc",
                                               "subreddit_name": "pics", "num_items": "5", "source": "relay"})
    assert reply.get_json()["status"] == "success"
    assert "1 used relay message(s) deleted" in reply.get_json()["message"]

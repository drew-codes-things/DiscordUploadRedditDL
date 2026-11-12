import pytest
import responses

import backend

TOKEN = "test-app-token"
WEBHOOK = "https://discord.com/api/webhooks/999/attacker"
FORM = {"webhook_url": WEBHOOK, "subreddit_name": "pics", "num_items": "1"}
MEDIA_POST = {
    "id": "abc",
    "title": "A post",
    "permalink_full": "https://www.reddit.com/r/pics/comments/abc/a_post/",
    "media": {"video_url": None, "image_url": "https://i.redd.it/abc.jpg"},
}


@pytest.fixture(autouse=True)
def app_settings(monkeypatch):
    monkeypatch.setattr(backend, "APP_TOKEN", TOKEN)
    monkeypatch.setattr(backend, "CONFIGURED_APP_TOKEN", "")
    monkeypatch.setattr(backend, "ALLOWED_HOSTS", backend.parse_allowed_hosts("", "127.0.0.1"))
    monkeypatch.setattr(backend, "save_sent_posts", lambda posts: None)
    monkeypatch.setattr(backend, "load_sent_posts", lambda: {})
    monkeypatch.setattr(backend, "WEBHOOK_POST_DELAY", 0)
    monkeypatch.setattr(backend, "load_reddit_posts", lambda source, name, limit: [dict(MEDIA_POST)])


def post(path, headers=None, host="localhost:1432"):
    client = backend.app.test_client()
    return client.post(path, data=FORM, headers=headers or {}, base_url=f"http://{host}")


@responses.activate
def test_cross_site_post_is_refused_even_with_the_token():
    reply = post("/fetch_reddit", {"Origin": "https://evil.example", backend.APP_TOKEN_HEADER: TOKEN})
    assert reply.status_code == 403
    assert len(responses.calls) == 0


@responses.activate
def test_null_origin_is_refused():
    reply = post("/fetch_reddit", {"Origin": "null", backend.APP_TOKEN_HEADER: TOKEN})
    assert reply.status_code == 403
    assert len(responses.calls) == 0


@responses.activate
def test_other_local_port_is_a_different_origin():
    reply = post("/fetch_reddit", {"Origin": "http://localhost:8080", backend.APP_TOKEN_HEADER: TOKEN})
    assert reply.status_code == 403


@responses.activate
@pytest.mark.parametrize("path", ["/fetch_reddit", "/upload", "/preview_reddit"])
def test_posts_without_the_token_are_refused(path):
    reply = post(path, {"Origin": "http://localhost:1432"})
    assert reply.status_code == 403
    assert len(responses.calls) == 0


@responses.activate
def test_wrong_token_is_refused():
    reply = post("/fetch_reddit", {backend.APP_TOKEN_HEADER: "nope"})
    assert reply.status_code == 403


@responses.activate
def test_same_origin_post_with_the_token_is_served():
    responses.post(WEBHOOK, status=204)
    reply = post("/fetch_reddit", {"Origin": "http://localhost:1432", backend.APP_TOKEN_HEADER: TOKEN})
    assert reply.status_code == 200
    assert reply.get_json()["status"] == "success"


@responses.activate
def test_unknown_host_header_is_refused_for_every_request():
    client = backend.app.test_client()
    assert client.get("/", base_url="http://rebound.evil.example:1432").status_code == 403
    reply = post("/fetch_reddit", {backend.APP_TOKEN_HEADER: TOKEN}, host="rebound.evil.example:1432")
    assert reply.status_code == 403
    assert len(responses.calls) == 0


def test_page_carries_the_generated_token_for_local_use():
    page = backend.app.test_client().get("/", base_url="http://localhost:1432")
    assert page.status_code == 200
    assert f'content="{TOKEN}"' in page.get_data(as_text=True)


def test_page_never_carries_a_configured_token(monkeypatch):
    monkeypatch.setattr(backend, "CONFIGURED_APP_TOKEN", TOKEN)
    page = backend.app.test_client().get("/", base_url="http://localhost:1432").get_data(as_text=True)
    assert TOKEN not in page
    assert 'id="app-token"' in page


def test_health_stays_open():
    assert backend.app.test_client().get("/health", base_url="http://127.0.0.1:1432").status_code == 200


def test_default_bind_is_loopback(monkeypatch):
    monkeypatch.delenv("BIND_HOST", raising=False)
    assert backend.bind_host_from_env() == "127.0.0.1"
    monkeypatch.setenv("BIND_HOST", "0.0.0.0")
    assert backend.bind_host_from_env() == "0.0.0.0"


def test_wide_bind_without_a_configured_token_refuses_to_start():
    with pytest.raises(RuntimeError, match="APP_TOKEN"):
        backend.check_startup_settings("0.0.0.0", "")
    backend.check_startup_settings("0.0.0.0", "set")
    backend.check_startup_settings("127.0.0.1", "")


def test_allowed_hosts_include_loopback_the_bind_address_and_extras():
    hosts = backend.parse_allowed_hosts("Upload.Example, 192.168.1.20", "10.0.0.5")
    assert {"localhost", "127.0.0.1", "::1", "upload.example", "192.168.1.20", "10.0.0.5"} <= hosts
    assert "0.0.0.0" not in backend.parse_allowed_hosts("", "0.0.0.0")

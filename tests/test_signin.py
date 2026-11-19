import ipaddress
import logging
import os
import shutil
import stat
import subprocess
import sys

import pytest
import responses

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend
from signin import SESSION_SECONDS, FailureLimiter, OwnerAccount

REPO = os.path.join(os.path.dirname(__file__), "..")
COOKIE = "discordupload_session"
OWNER_NAME = "owner"
PASSWORD = "correct horse battery"
TOKEN = "test-app-token"
HEADER = "X-Forwarded-User"
WEBHOOK = "https://discord.com/api/webhooks/999/owner"
FORM = {"webhook_url": WEBHOOK, "subreddit_name": "pics", "num_items": "1"}
MEDIA_POST = {
    "id": "abc",
    "title": "A post",
    "permalink_full": "https://www.reddit.com/r/pics/comments/abc/a_post/",
    "media": {"video_url": None, "image_url": "https://i.redd.it/abc.jpg"},
}


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def web(tmp_path, monkeypatch, clock):
    monkeypatch.setattr(backend, "APP_TOKEN", TOKEN)
    monkeypatch.setattr(backend, "CONFIGURED_APP_TOKEN", "")
    monkeypatch.setattr(backend, "ALLOW_INSECURE", False)
    monkeypatch.setattr(backend, "ALLOWED_HOSTS", backend.parse_allowed_hosts("", "127.0.0.1"))
    monkeypatch.setattr(backend, "save_sent_posts", lambda posts: None)
    monkeypatch.setattr(backend, "load_sent_posts", lambda: {})
    monkeypatch.setattr(backend, "WEBHOOK_POST_DELAY", 0)
    monkeypatch.setattr(backend, "load_reddit_posts", lambda source, name, limit: [dict(MEDIA_POST)])
    monkeypatch.setattr(backend.OWN_SIGN_IN, "owner", OwnerAccount(tmp_path / "owner.json"))
    monkeypatch.setattr(backend.OWN_SIGN_IN, "limiter", FailureLimiter(clock=clock))
    monkeypatch.setattr(backend.OWN_SIGN_IN, "device_limiter", FailureLimiter(clock=clock, before_strict=None))
    monkeypatch.setattr(backend.OWN_SIGN_IN, "clock", clock)
    monkeypatch.setattr(backend.OWN_SIGN_IN, "_setup_code", None)
    backend.limiter.reset()
    return backend.app.test_client()


def set_up_owner(web, form=None, **kwargs):
    details = {"code": backend.OWN_SIGN_IN.setup_code(), "user": OWNER_NAME, "password": PASSWORD, "confirm": PASSWORD}
    details.update(form or {})
    return web.post("/setup", data=details, **kwargs)


def sign_in(web, password=PASSWORD, **kwargs):
    return web.post("/signin", data={"user": OWNER_NAME, "password": password}, **kwargs)


def forget_the_browser(web) -> None:
    web.delete_cookie(COOKIE)
    web.delete_cookie(COOKIE + "_device", path="/signin")


def session_cookie(response) -> str:
    return next(value for value in response.headers.getlist("Set-Cookie") if value.startswith(COOKIE + "="))


def send_posts(web, token=TOKEN, **headers):
    return web.post("/fetch_reddit", data=FORM, headers={backend.APP_TOKEN_HEADER: token, **headers})


def test_the_own_sign_in_is_the_default(web):
    assert backend.sign_in_method() == "builtin"


def test_a_signed_out_visit_goes_to_setup_then_to_sign_in(web):
    assert web.get("/").headers["Location"].endswith("/setup")
    set_up_owner(web)
    web.delete_cookie(COOKIE)
    assert web.get("/").headers["Location"].endswith("/signin")


@responses.activate
@pytest.mark.parametrize("path", ["/fetch_reddit", "/upload", "/preview_reddit"])
def test_posts_need_a_sign_in_even_with_the_token(web, path):
    reply = web.post(path, data=FORM, headers={backend.APP_TOKEN_HEADER: TOKEN, "Origin": "http://localhost"})
    assert reply.status_code == 401
    assert len(responses.calls) == 0


def test_the_signed_out_page_does_not_hand_out_the_token(web):
    assert TOKEN not in web.get("/").get_data(as_text=True)


def test_the_health_check_stays_open(web):
    assert web.get("/health").status_code == 200


@responses.activate
def test_the_owner_sends_posts_after_setup(web, tmp_path):
    responses.post(WEBHOOK, status=204)
    assert set_up_owner(web).status_code == 303
    assert stat.S_IMODE(os.stat(tmp_path / "owner.json").st_mode) == 0o600
    page = web.get("/").get_data(as_text=True)
    assert f'content="{TOKEN}"' in page and 'href="/signout"' in page
    reply = send_posts(web, Origin="http://localhost")
    assert reply.status_code == 200
    assert reply.get_json()["status"] == "success"


@responses.activate
def test_a_signed_in_post_still_needs_the_token_and_its_own_origin(web):
    set_up_owner(web)
    assert send_posts(web, token="nope").status_code == 403
    assert send_posts(web, Origin="https://evil.example").status_code == 403
    assert len(responses.calls) == 0


@responses.activate
def test_the_user_header_is_ignored(web):
    set_up_owner(web)
    web.delete_cookie(COOKIE)
    assert send_posts(web, **{HEADER: OWNER_NAME}).status_code == 401
    assert len(responses.calls) == 0


def test_setup_needs_the_code_and_happens_once(web):
    assert set_up_owner(web, form={"code": "not-the-code"}).status_code == 401
    assert set_up_owner(web).status_code == 303
    assert web.get("/").status_code == 200
    assert set_up_owner(web, form={"user": "intruder"}).headers["Location"].endswith("/signin")
    assert backend.OWN_SIGN_IN.owner.read()["user"] == OWNER_NAME


def test_wrong_passwords_are_rate_limited(web):
    set_up_owner(web)
    forget_the_browser(web)
    for _attempt in range(5):
        assert sign_in(web, password="wrong password!").status_code == 401
    assert sign_in(web).status_code == 429
    assert sign_in(web, environ_base={"REMOTE_ADDR": "192.0.2.7"}).status_code == 303


def test_signing_out_and_expiry_end_the_session(web, clock):
    set_up_owner(web)
    assert web.get("/").status_code == 200
    clock.now += SESSION_SECONDS + 1
    assert web.get("/").status_code == 303
    clock.now -= SESSION_SECONDS + 1
    assert web.get("/").status_code == 200
    assert web.post("/signout").status_code == 303
    assert web.get("/").status_code == 303


@pytest.mark.parametrize("token", ["é.é", "abc.\udcff", "no-dot", "", None])
def test_an_odd_session_value_is_refused_not_crashed(web, token):
    assert backend.OWN_SIGN_IN.user_for_token(token) is None


def test_the_session_cookie_flags(web, monkeypatch):
    local = set_up_owner(web)
    assert "HttpOnly" in session_cookie(local) and "SameSite=Lax" in session_cookie(local)
    assert "Secure" not in session_cookie(local)
    monkeypatch.setattr(backend, "ALLOWED_HOSTS", backend.parse_allowed_hosts("192.0.2.1", "127.0.0.1"))
    remote = sign_in(web, base_url="http://192.0.2.1")
    assert "Secure" in session_cookie(remote)


def test_the_no_sign_in_setting_keeps_the_local_page(web, monkeypatch):
    monkeypatch.setattr(backend, "ALLOW_INSECURE", True)
    assert backend.sign_in_method() == "none"
    page = web.get("/")
    assert page.status_code == 200 and f'content="{TOKEN}"' in page.get_data(as_text=True)
    assert web.get("/setup").status_code == 404
    assert web.get("/signin").status_code == 404


@responses.activate
def test_a_configured_app_token_keeps_its_meaning(web, monkeypatch):
    responses.post(WEBHOOK, status=204)
    monkeypatch.setattr(backend, "CONFIGURED_APP_TOKEN", TOKEN)
    assert backend.sign_in_method() == "token"
    page = web.get("/")
    assert page.status_code == 200 and TOKEN not in page.get_data(as_text=True)
    assert web.get("/setup").status_code == 404
    assert send_posts(web).status_code == 200


def test_only_the_no_sign_in_setting_is_kept_on_loopback():
    with pytest.raises(RuntimeError, match="APP_TOKEN"):
        backend.check_startup_settings("0.0.0.0", "none")
    backend.check_startup_settings("0.0.0.0", "builtin")
    backend.check_startup_settings("0.0.0.0", "token")
    backend.check_startup_settings("127.0.0.1", "none")


def test_starting_without_a_sign_in_says_so_loudly(caplog):
    caplog.set_level(logging.INFO)
    backend.check_startup_settings("127.0.0.1", "none")
    warnings = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "ALLOW_INSECURE=true" in warnings[0] and "no sign-in" in warnings[0]


@pytest.mark.parametrize("method", ["builtin", "token"])
def test_starting_with_a_sign_in_gives_no_such_warning(caplog, method):
    caplog.set_level(logging.INFO)
    backend.check_startup_settings("127.0.0.1", method)
    assert [record for record in caplog.records if record.levelno >= logging.WARNING] == []


def import_app(tmp_path, shown="backend.OWN_SIGN_IN.secret.decode()", **settings):
    copy = tmp_path / "app"
    if not copy.exists():
        shutil.copytree(REPO, copy, ignore=shutil.ignore_patterns("tests", ".git", "__pycache__", "*.json", ".env",
                                                                    "secret_key"))
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)}
    env.update(settings)
    return subprocess.run([sys.executable, "-c", f"import backend; print({shown})"], cwd=copy, env=env,
                          capture_output=True, text=True, timeout=60)


def test_the_sign_in_key_is_saved_and_reused_when_imported(tmp_path):
    first = import_app(tmp_path)
    second = import_app(tmp_path)
    assert first.returncode == 0, first.stderr
    key_file = tmp_path / "app" / "secret_key"
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert first.stdout.strip() == second.stdout.strip() == key_file.read_text()


@pytest.mark.parametrize("settings", [{"SECRET_KEY": "a"}, {"SECRET_KEY": "y" * 31}])
def test_a_short_sign_in_key_is_refused(tmp_path, settings):
    started = import_app(tmp_path, **settings)
    assert started.returncode != 0
    assert "SECRET_KEY holds" in started.stderr


def test_a_short_key_file_is_refused(tmp_path):
    import_app(tmp_path, SECRET_KEY="z" * 32)
    (tmp_path / "app" / "secret_key").write_bytes(b"short")
    started = import_app(tmp_path)
    assert started.returncode != 0
    assert "fewer than the 32" in started.stderr


def test_the_other_modes_need_no_key_file_and_take_any_key(tmp_path):
    assert import_app(tmp_path, ALLOW_INSECURE="true", SECRET_KEY="a", TRUSTED_PROXIES="0.0.0.0/0").returncode == 0
    assert import_app(tmp_path, APP_TOKEN="a configured token").returncode == 0
    assert not (tmp_path / "app" / "secret_key").exists()


def test_trusted_proxies_come_from_the_environment(tmp_path):
    shown = "backend.OWN_SIGN_IN.client_address('192.0.2.10', {'X-Forwarded-For': '203.0.113.9'})"
    started = import_app(tmp_path, shown, TRUSTED_PROXIES="192.0.2.10")
    assert started.returncode == 0, started.stderr
    assert started.stdout.split() == ["203.0.113.9"]
    assert import_app(tmp_path, shown).stdout.split() == ["192.0.2.10"]


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "10.0.0.5/8", "not-an-address"])
def test_trusted_proxies_that_reach_too_far_are_refused(tmp_path, value):
    started = import_app(tmp_path, TRUSTED_PROXIES=value)
    assert started.returncode != 0
    assert "TRUSTED_PROXIES" in started.stderr


def test_a_rebinding_host_name_never_reaches_the_sign_in(web):
    set_up_owner(web)
    attacker = backend.app.test_client()
    for _attempt in range(6):
        assert sign_in(attacker, password="wrong password!", base_url="http://rebind.evil.example:1432").status_code == 403
    assert attacker.get("/", base_url="http://rebind.evil.example:1432").status_code == 403
    assert sign_in(attacker).status_code == 303


def test_a_browser_that_signed_in_before_is_not_locked_out_by_others(web):
    set_up_owner(web)
    assert web.post("/signout").status_code == 303
    attacker = backend.app.test_client()
    for _attempt in range(5):
        assert sign_in(attacker, password="wrong password!").status_code == 401
    assert sign_in(attacker).status_code == 429
    assert sign_in(web).status_code == 303


def test_the_forwarded_address_counts_only_from_a_trusted_proxy(web, monkeypatch):
    monkeypatch.setattr(backend.OWN_SIGN_IN, "trusted_proxies", (ipaddress.ip_network("192.0.2.10"),))
    set_up_owner(web)
    via_proxy = {"REMOTE_ADDR": "192.0.2.10"}
    attacker = backend.app.test_client()
    for _attempt in range(5):
        sign_in(attacker, password="wrong password!", environ_base=via_proxy, headers={"X-Forwarded-For": "203.0.113.9"})
    assert sign_in(attacker, environ_base=via_proxy, headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 429
    owner = backend.app.test_client()
    assert sign_in(owner, environ_base=via_proxy, headers={"X-Forwarded-For": "198.51.100.4"}).status_code == 303

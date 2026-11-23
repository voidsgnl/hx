from datetime import datetime, timedelta, timezone

from hx.fastpath import FastPath


def cookie(name, value, domain, **extra):
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": "/",
        "secure": False,
        "expires": -1,
        **extra,
    }


def test_domain_cookie_is_sent_to_target_subdomains():
    fast = FastPath()
    fast.set_allowed_domains({"app.example.test"})
    cookies = [cookie("session", "abc", ".example.test")]

    assert fast._cookies(cookies, "https://app.example.test/") == {
        "session": "abc"
    }
    assert fast._cookies(cookies, "https://api.app.example.test/v1") == {
        "session": "abc"
    }


def test_host_only_cookie_is_not_sent_to_subdomains():
    fast = FastPath()
    fast.set_allowed_domains({"app.example.test"})
    cookies = [cookie("session", "abc", "app.example.test")]

    assert fast._cookies(cookies, "https://app.example.test/") == {
        "session": "abc"
    }
    assert fast._cookies(cookies, "https://api.app.example.test/") == {}


def test_domain_match_rejects_suffix_confusion_and_unrelated_domains():
    fast = FastPath()
    fast.set_allowed_domains({"app.example.test"})
    cookies = [
        cookie("bad1", "x", ".notexample.test"),
        cookie("bad2", "x", ".evil.test"),
    ]

    assert fast._cookies(cookies, "https://app.example.test/") == {}


def test_cookie_path_secure_and_expiry_are_respected():
    fast = FastPath()
    fast.set_allowed_domains({"app.example.test"})
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()
    cookies = [
        cookie("root", "yes", "app.example.test", path="/"),
        cookie("admin", "yes", "app.example.test", path="/admin"),
        cookie("secure", "yes", "app.example.test", secure=True),
        cookie("expired", "yes", "app.example.test", expires=expired),
        cookie("zero_expiry", "yes", "app.example.test", expires=0),
    ]

    assert fast._cookies(cookies, "http://app.example.test/admin/page") == {
        "root": "yes",
        "admin": "yes",
    }
    assert fast._cookies(cookies, "https://app.example.test/public") == {
        "root": "yes",
        "secure": "yes",
    }


def test_redirect_recalculates_cookie_scope(monkeypatch):
    calls = []

    class Response:
        def __init__(self, status, location=None):
            self.status_code = status
            self.headers = {"Location": location} if location else {}

    def fake_request(method, url, **kwargs):
        calls.append((url, kwargs.get("cookies")))
        if url == "https://app.example.test/start":
            return Response(302, "https://evil.test/landing")
        return Response(200)

    monkeypatch.setattr("hx.fastpath.cffi.request", fake_request)
    fast = FastPath()
    fast.set_allowed_domains({"app.example.test"})
    fast._request(
        "GET",
        "https://app.example.test/start",
        browser_cookies=[cookie("session", "secret", ".example.test")],
    )

    assert calls == [
        ("https://app.example.test/start", {"session": "secret"}),
        ("https://evil.test/landing", {}),
    ]


def test_request_spec_state_wins_and_is_not_forwarded_off_domain(monkeypatch):
    calls = []

    class Response:
        def __init__(self, status, location=None):
            self.status_code = status
            self.headers = {"Location": location} if location else {}

    def fake_request(method, url, **kwargs):
        calls.append((url, kwargs))
        if url == "https://app.example.test/start":
            return Response(302, "https://evil.test/landing")
        return Response(200)

    monkeypatch.setattr("hx.fastpath.cffi.request", fake_request)
    fast = FastPath()
    fast.set_allowed_domains({"app.example.test"})
    fast._request(
        "GET",
        "https://app.example.test/start",
        headers={"X-Test-Auth": "secret"},
        browser_cookies=[cookie("session", "browser", "app.example.test")],
        spec_cookies={"session": "spec", "extra": "cookie"},
    )

    assert calls[0][1]["headers"] == {"X-Test-Auth": "secret"}
    assert calls[0][1]["cookies"] == {
        "session": "spec",
        "extra": "cookie",
    }
    assert "headers" not in calls[1][1]
    assert calls[1][1]["cookies"] == {}

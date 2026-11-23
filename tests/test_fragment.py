from urllib.parse import urlparse, parse_qs

from hx.scanner import _fragment_query, _with_fragment_param


def test_extracts_parameters_from_hash_router_query():
    assert _fragment_query("/search?q=test&page=2") == {
        "q": ["test"],
        "page": ["2"],
    }


def test_extracts_parameters_from_plain_fragment_query():
    assert _fragment_query("q=test&empty=") == {
        "q": ["test"],
        "empty": [""],
    }


def test_ignores_route_without_query_parameters():
    assert _fragment_query("/dashboard") == {}


def test_replaces_parameter_and_preserves_hash_route():
    url = "https://example.test/#/search?q=old&page=2"
    updated = _with_fragment_param(url, "q", "new value")
    parts = urlparse(updated)
    assert parts.path == "/"
    assert parts.fragment.startswith("/search?")
    assert parse_qs(parts.fragment.split("?", 1)[1]) == {
        "q": ["new value"],
        "page": ["2"],
    }


def test_adds_query_to_route_without_existing_query():
    updated = _with_fragment_param(
        "https://example.test/#/search", "q", "test"
    )
    assert urlparse(updated).fragment == "/search?q=test"


def test_preserves_plain_fragment_query_format():
    updated = _with_fragment_param(
        "https://example.test/#q=old&page=2", "q", "new"
    )
    assert urlparse(updated).fragment == "q=new&page=2"

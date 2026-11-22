"""POST navigation shim for the oracle.

The oracle's contract is: navigate the browser context to something, observe
execution hits. For GET that "something" is a URL. For POST there is no URL
that reproduces the request, so we synthesize one: a tiny data-URL page that
auto-submits a form (or fires a fetch) to the target, then let the target's
response page execute.

The oracle's init script is installed on every frame by add_init_script, so
hits recorded on the POST response page are collected exactly as for GET.
"""
from urllib.parse import urlencode
import json
import html


def _attr(s: str) -> str:
    """Escape a value for use inside a double-quoted HTML attribute."""
    return html.escape(s, quote=True)


def form_submit_page(action: str, fields: dict[str, str]) -> str:
    """data: URL that POSTs form-encoded fields to `action` on load."""
    inputs = "".join(
        f'<input type="hidden" name="{_attr(k)}" value="{_attr(v)}">'
        for k, v in fields.items()
    )
    return (
        "data:text/html;charset=utf-8,"
        + (
            f"""<!doctype html><html><body>
<form id="f" method="POST" action="{_attr(action)}">{inputs}</form>
<script>document.getElementById('f').submit();</script>
</body></html>"""
        ).replace("\n", " ")
    )


def json_fetch_page(action: str, body: dict) -> str:
    """data: URL that POSTs a JSON body to `action`, then renders the response
    as the document so the oracle observes execution in the response context."""
    payload = json.dumps(body)
    return (
        "data:text/html;charset=utf-8,"
        + (
            f"""<!doctype html><html><body><script>
window.__hx_internal = true;
fetch({json.dumps(action)}, {{
  method: 'POST',
  headers: {{'Content-Type': 'application/json'}},
  body: {json.dumps(payload)}
}}).then(r => r.text()).then(t => {{
  window.__hx_internal = false;
  document.open(); document.write(t); document.close();
}});
</script></body></html>"""
        ).replace("\n", " ")
    )
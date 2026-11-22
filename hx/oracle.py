"""Execution oracle: prove XSS by observing execution, not by matching text.

Every injected payload carries a unique payload_id. The init script records
hits tagged with whatever payload_id is active. probe() sets the id, navigates,
waits for async execution, then reads hits back. A hit whose detail contains
the id = proven execution of THAT payload.
"""
import asyncio
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

ORACLE_INIT_JS = """
window.__hx_active_id = null;
try {
  window.__hx_active_id = sessionStorage.getItem("__hx_active_payload_id");
} catch (_) {}
window.__hx_hits = [];
window.__hx_record = function(kind, detail) {
  window.__hx_hits.push({
    kind: kind,
    detail: String(detail).slice(0, 300),
    id: window.__hx_active_id,
    ts: Date.now(),
  });
};
const _alert = window.alert;
window.alert = function(m){ window.__hx_record('alert', m); };
const _confirm = window.confirm;
window.confirm = function(m){ window.__hx_record('confirm', m); return true; };
const _prompt = window.prompt;
window.prompt = function(m){ window.__hx_record('prompt', m); return ''; };
const _eval = window.eval;
window.eval = function(c){
  const source = String(c);
  if (
    !window.__hx_internal
    && source !== "window.__hx_hits"
    && source !== "() => window.__hx_hits"
    && source !== "() => { window.__hx_internal = true; return window.__hx_hits; }"
    && source !== "() => { window.__hx_internal = false; }"
  ) {
    window.__hx_record('eval', source);
  }
  return _eval(c);
};
"""

@dataclass
class Hit:
    kind: str
    detail: str
    payload_id: str | None

@dataclass
class ProbeResult:
    proven: bool
    payload_id: str
    hits: list[Hit]


def make_payload_id() -> str:
    return "hx" + uuid.uuid4().hex[:12]


async def _read_hits(page) -> list:
    raw = await page.evaluate(
        "() => { window.__hx_internal = true; return window.__hx_hits; }"
    )
    await page.evaluate("() => { window.__hx_internal = false; }")
    return raw or []


async def probe(page, url: str, payload: str, settle: float = 1.2) -> ProbeResult:
    """Navigate to url (already containing payload), collect execution hits."""
    pid = make_payload_id()
    # sessionStorage survives navigation, unlike window state recreated by init scripts.
    await page.evaluate(
        "({id}) => { "
        "  sessionStorage.setItem('__hx_active_payload_id', id); "
        "  window.__hx_active_id = id; "
        "  window.__hx_hits = []; "
        "}",
        {"id": pid},
    )
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        # navigation may fail mid-redirect; hits collected so far still valid
        pass
    await asyncio.sleep(settle)
    raw = await _read_hits(page)
    hits = [Hit(kind=h["kind"], detail=h["detail"], payload_id=h.get("id"))
            for h in (raw or [])]
    proven = any(
        h.payload_id == pid and h.kind in ("alert", "confirm", "prompt", "eval")
        for h in hits
    )
    return ProbeResult(proven=proven, payload_id=pid, hits=hits)

from hx.submit import form_submit_page, json_fetch_page

async def probe_post_form(page, action: str, fields: dict[str, str],
                          settle: float = 1.5) -> ProbeResult:
    pid = make_payload_id()
    parsed = urlparse(action)
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    try:
        await page.goto(origin, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass
    await page.evaluate(
        "({id}) => { "
        "  sessionStorage.setItem('__hx_active_payload_id', id); "
        "  window.__hx_active_id = id; "
        "  window.__hx_hits = []; "
        "}",
        {"id": pid},
    )
    try:
        await page.evaluate(
            """async ({action, fields}) => {
              const form = document.createElement('form');
              form.method = 'POST';
              form.action = action;
              for (const [name, value] of Object.entries(fields)) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = name;
                input.value = value;
                form.appendChild(input);
              }
              document.body.appendChild(form);
              form.submit();
            }""",
            {"action": action, "fields": fields},
        )
    except Exception:
        pass
    await asyncio.sleep(settle)
    raw = await _read_hits(page)
    hits = [Hit(kind=h["kind"], detail=h["detail"], payload_id=h.get("id"))
            for h in (raw or [])]
    proven = any(
        h.payload_id == pid and h.kind in ("alert", "confirm", "prompt", "eval")
        for h in hits
    )
    return ProbeResult(proven=proven, payload_id=pid, hits=hits)


async def probe_post_json(page, action: str, body: dict,
                          settle: float = 1.8) -> ProbeResult:
    pid = make_payload_id()
    parsed = urlparse(action)
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    try:
        await page.goto(origin, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass
    await page.evaluate(
        "({id}) => { "
        "  sessionStorage.setItem('__hx_active_payload_id', id); "
        "  window.__hx_active_id = id; "
        "  window.__hx_hits = []; "
        "}",
        {"id": pid},
    )
    try:
        await page.evaluate(
            """async ({action, body}) => {
              window.__hx_internal = true;
              const response = await fetch(action, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)
              });
              const text = await response.text();
              window.__hx_internal = false;
              document.open();
              document.write(text);
              document.close();
            }""",
            {"action": action, "body": body},
        )
    except Exception:
        pass
    await asyncio.sleep(settle)   # fetch + document.write needs a beat longer
    raw = await _read_hits(page)
    hits = [Hit(kind=h["kind"], detail=h["detail"], payload_id=h.get("id"))
            for h in (raw or [])]
    proven = any(
        h.payload_id == pid and h.kind in ("alert", "confirm", "prompt", "eval")
        for h in hits
    )
    return ProbeResult(proven=proven, payload_id=pid, hits=hits)
"""Execution oracle: prove XSS by matching execution to a unique payload marker.

A probe ID is embedded in the payload itself. Browser events are attributed to
that probe only when the event carries the same ID in its execution details;
the session ID alone is never sufficient evidence.
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
window.alert = function(m) { window.__hx_record("alert", m); };
window.confirm = function(m) {
  window.__hx_record("confirm", m);
  return true;
};
window.prompt = function(m) {
  window.__hx_record("prompt", m);
  return "";
};
const _eval = window.eval;
window.eval = function(c) {
  const source = String(c);
  if (!window.__hx_internal) {
    window.__hx_record("eval", source);
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
    """Return a fresh, unpredictable marker to embed in one probe payload."""
    return "hx" + uuid.uuid4().hex


async def _prepare_probe(page, payload_id: str) -> None:
    await page.evaluate(
        """({id}) => {
          sessionStorage.setItem("__hx_active_payload_id", id);
          window.__hx_active_id = id;
          window.__hx_hits = [];
        }""",
        {"id": payload_id},
    )


async def _read_hits(page) -> list:
    raw = await page.evaluate(
        "() => { window.__hx_internal = true; return window.__hx_hits || []; }"
    )
    await page.evaluate("() => { window.__hx_internal = false; }")
    return raw or []


async def _collect_result(page, payload_id: str) -> ProbeResult:
    raw = await _read_hits(page)
    hits = [
        Hit(kind=h["kind"], detail=h["detail"], payload_id=h.get("id"))
        for h in raw
    ]
    # The active session ID labels the browsing attempt, not the cause of an
    # event. Require the unpredictable marker to appear in the event details.
    proven = any(
        hit.payload_id == payload_id
        and payload_id in hit.detail
        and hit.kind in ("alert", "confirm", "prompt", "eval")
        for hit in hits
    )
    return ProbeResult(proven=proven, payload_id=payload_id, hits=hits)


async def probe(
    page, url: str, payload: str, *, payload_id: str, settle: float = 1.2
) -> ProbeResult:
    """Navigate to a payload URL and prove only execution carrying payload_id."""
    await _prepare_probe(page, payload_id)
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        # A redirect or navigation failure may occur after script execution.
        pass
    await asyncio.sleep(settle)
    return await _collect_result(page, payload_id)


async def probe_post_form(
    page,
    action: str,
    fields: dict[str, str],
    *,
    payload_id: str,
    settle: float = 1.5,
) -> ProbeResult:
    parsed = urlparse(action)
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    try:
        await page.goto(origin, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass
    await _prepare_probe(page, payload_id)
    try:
        await page.evaluate(
            """({action, fields}) => {
              const form = document.createElement("form");
              form.method = "POST";
              form.action = action;
              for (const [name, value] of Object.entries(fields)) {
                const input = document.createElement("input");
                input.type = "hidden";
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
    return await _collect_result(page, payload_id)


async def probe_post_json(
    page,
    action: str,
    body: dict,
    *,
    payload_id: str,
    settle: float = 1.8,
) -> ProbeResult:
    parsed = urlparse(action)
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    try:
        await page.goto(origin, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass
    await _prepare_probe(page, payload_id)
    try:
        await page.evaluate(
            """async ({action, body}) => {
              let text;
              window.__hx_internal = true;
              try {
                const response = await fetch(action, {
                  method: "POST",
                  headers: {"Content-Type": "application/json"},
                  body: JSON.stringify(body)
                });
                text = await response.text();
              } finally {
                window.__hx_internal = false;
              }
              document.open();
              document.write(text);
              document.close();
            }""",
            {"action": action, "body": body},
        )
    except Exception:
        pass
    await asyncio.sleep(settle)
    return await _collect_result(page, payload_id)

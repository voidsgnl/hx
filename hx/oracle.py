"""Execution oracle: prove XSS with a payload-specific browser callback.

Each payload embeds a fresh probe ID and calls the protected __hx_proof
callback. Generic page JavaScript activity is recorded for diagnostics but
cannot, by itself, produce a confirmed XSS finding.
"""
import asyncio
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse


ORACLE_INIT_JS = """
(() => {
  const hits = [];
  const record = (kind, detail, id = null) => {
    hits.push({
      kind,
      detail: String(detail).slice(0, 300),
      id,
      ts: Date.now(),
    });
  };

  Object.defineProperty(window, "__hx_hits", {
    configurable: false,
    get: () => hits,
  });
  Object.defineProperty(window, "__hx_reset", {
    configurable: false,
    writable: false,
    value: () => { hits.length = 0; },
  });
  Object.defineProperty(window, "__hx_proof", {
    configurable: false,
    writable: false,
    value: (id) => {
      // The unpredictable ID is embedded in exactly one probe payload.
      // Record it directly so execution remains attributable after a
      // cross-origin redirect, where sessionStorage is a different store.
      if (typeof id === "string") {
        record("proof", id, id);
      }
    },
  });

  window.alert = (message) => record("alert", message);
  window.confirm = (message) => {
    record("confirm", message);
    return true;
  };
  window.prompt = (message) => {
    record("prompt", message);
    return "";
  };
})();
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
    # Reset the current document's telemetry. Proof attribution travels with
    # the unpredictable ID embedded in the payload, not origin-scoped storage.
    await page.evaluate("() => window.__hx_reset()")


async def _read_hits(page) -> list:
    raw = await page.evaluate("() => window.__hx_hits || []")
    return raw or []


async def _collect_result(page, payload_id: str) -> ProbeResult:
    raw = await _read_hits(page)
    hits = [
        Hit(kind=h["kind"], detail=h["detail"], payload_id=h.get("id"))
        for h in raw
    ]
    # Only the protected callback embedded in our payload can prove execution.
    # Generic alerts, prompts, and other page activity are telemetry only.
    proven = any(
        hit.kind == "proof"
        and hit.payload_id == payload_id
        and hit.detail == payload_id
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
              const response = await fetch(action, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(body)
              });
              const text = await response.text();
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

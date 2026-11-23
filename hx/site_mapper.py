"""Read-only, same-origin website mapping for automated scan planning.

The mapper discovers rendered routes, forms, browser-observed API calls, and
bounded read-oriented UI interactions. It never submits forms or sends
vulnerability payloads.
"""
from __future__ import annotations

from collections import deque
import asyncio
from dataclasses import asdict, dataclass, field
import json
from urllib.parse import parse_qsl, parse_qs, urlencode, urljoin, urlsplit, urlunsplit

from hx.client import TargetClient
from hx.discover import discover_forms
from hx.oracle import ORACLE_INIT_JS
from hx.pacer import BudgetExhausted, Pacer


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    resource_type: str
    source_page: str
    query_parameters: list[str] = field(default_factory=list)
    request_body: dict | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    trigger: list[dict] | None = None

    def public_dict(self) -> dict:
        safe_headers = {
            key: (
                "<redacted>"
                if any(word in key.lower() for word in (
                    "authorization", "cookie", "token", "secret", "key", "credential"
                ))
                else value
            )
            for key, value in self.headers.items()
        }
        sensitive_words = (
            "password", "secret", "token", "key", "credential", "csrf",
            "session", "auth", "signature",
        )

        def redact_body(value):
            if isinstance(value, dict):
                return {
                    key: (
                        "<redacted>"
                        if any(word in str(key).lower() for word in sensitive_words)
                        else redact_body(child)
                    )
                    for key, child in value.items()
                }
            if isinstance(value, list):
                return [redact_body(child) for child in value]
            return value

        safe_body = redact_body(self.request_body or {})
        return {
            "url": self.url, "method": self.method,
            "resource_type": self.resource_type, "source_page": self.source_page,
            "query_parameters": self.query_parameters,
            "request_body": safe_body or None,
            "headers": safe_headers, "content_type": self.content_type,
            "body_parameters": sorted((self.request_body or {}).keys()),
            "trigger": self.trigger,
        }


@dataclass
class DiscoveredPage:
    url: str
    depth: int
    title: str
    status: int | None
    links: list[str] = field(default_factory=list)
    query_parameters: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    behaviour: str = "general"


@dataclass
class BehaviourGroup:
    name: str
    pages: list[str] = field(default_factory=list)
    form_signatures: list[str] = field(default_factory=list)
    endpoint_urls: list[str] = field(default_factory=list)


@dataclass
class SiteMapResult:
    target: str
    pages: list[DiscoveredPage] = field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    groups: list[BehaviourGroup] = field(default_factory=list)
    requests_used: int = 0
    interactions_attempted: int = 0
    budget_exhausted: bool = False
    pages_attempted: int = 0
    pages_failed: list[str] = field(default_factory=list)
    pages_pending: list[str] = field(default_factory=list)
    framework_requests: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['endpoints'] = [endpoint.public_dict() for endpoint in self.endpoints]
        return data

_ROUTE_CAPTURE_JS = """
(() => {
  if (window.__hx_routes) return;
  const routes = [];
  Object.defineProperty(window, "__hx_routes", {
    configurable: false,
    get: () => routes,
  });
  const record = () => {
    const current = location.href;
    if (!routes.includes(current)) routes.push(current);
  };
  for (const method of ["pushState", "replaceState"]) {
    const original = history[method].bind(history);
    history[method] = (...args) => {
      const result = original(...args);
      record();
      return result;
    };
  }
  addEventListener("hashchange", record);
  addEventListener("popstate", record);
})();
"""

_INTERACTION_CANDIDATES_JS = """
() => {
  const excluded = /\\b(log ?out|sign ?out|logout|delete|remove|destroy|save|submit|send|publish|create|update|edit|confirm|purchase|checkout|pay|transfer|invite|reset|cancel|approve|reject|accept|decline|continue|next|finish|upload|download)\\b/i;
  const nodes = Array.from(document.querySelectorAll(
    'button[type="button"], [role="button"], [role="tab"]'
  ));
  const counts = new Map();
  return nodes.map(element => {
    const role = element.getAttribute("role") || "button";
    const name = (element.getAttribute("aria-label") ||
      element.innerText || element.getAttribute("title") || "")
      .replace(/\\s+/g, " ").trim();
    const type = (element.getAttribute("type") || "").toLowerCase();
    const disabled = element.disabled ||
      element.getAttribute("aria-disabled") === "true";
    const insideForm = Boolean(element.closest("form"));
    const key = role + "\\u0000" + name;
    const matchIndex = counts.get(key) || 0;
    counts.set(key, matchIndex + 1);
    return {role, name, match_index: matchIndex,
      allowed: Boolean(name) && name.length <= 80 && !disabled &&
        !insideForm && !excluded.test(name) &&
        (element.tagName !== "BUTTON" || type === "button")};
  }).filter(item => item.allowed).slice(0, 4)
}
"""


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is None:
        port = 80 if scheme == "http" else 443 if scheme == "https" else None
    return scheme, host, port


def _is_in_scope(url: str, base_url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme in ("http", "https") and _origin(url) == _origin(base_url)


def _page_key(url: str) -> str:
    """Deduplicate parameter values while preserving route and parameter names."""
    parts = urlsplit(url)
    query_keys = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})
    fragment = parts.fragment
    if "?" in fragment:
        route, fragment_query = fragment.split("?", 1)
        fragment_keys = sorted({
            key for key, _ in parse_qsl(fragment_query, keep_blank_values=True)
        })
        fragment = route + ("?" + urlencode([(key, "") for key in fragment_keys]) if fragment_keys else "")
    elif "=" in fragment or "&" in fragment:
        fragment_keys = sorted({
            key for key, _ in parse_qsl(fragment, keep_blank_values=True)
        })
        fragment = urlencode([(key, "") for key in fragment_keys])
    return urlunsplit((
        parts.scheme.lower(), parts.netloc.lower(), parts.path or "/",
        urlencode([(key, "") for key in query_keys]), fragment,
    ))


def _mapping_request_allowed(
    request_url: str,
    resource_type: str,
    base_url: str,
) -> bool:
    """Keep requests useful for DOM/API discovery; skip heavy passive assets."""
    if not _is_in_scope(request_url, base_url):
        return False
    if resource_type.lower() in {"image", "font", "media"}:
        return False
    return True


def _is_framework_navigation_request(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
) -> bool:
    """Identify framework transport requests without hiding application POST actions."""
    parts = urlsplit(url)
    query_names = {
        name.lower() for name, _ in parse_qsl(parts.query, keep_blank_values=True)
    }
    normalized_headers = {
        key.lower(): value.lower() for key, value in (headers or {}).items()
    }
    accept = normalized_headers.get("accept", "")
    framework_asset = parts.path.startswith(("/_next/", "/_nuxt/"))
    framework_get = method.upper() == "GET" and (
        "_rsc" in query_names
        or normalized_headers.get("rsc") == "1"
        or "text/x-component" in accept
    )
    return framework_asset or framework_get


def _behaviour_for(url: str, forms: list[dict]) -> str:
    path = urlsplit(url).path.lower()
    names = {
        field.get("name", "").lower()
        for form in forms for field in form.get("fields", [])
    }
    if any(word in path for word in ("login", "signin", "auth", "register", "password")) or names & {
        "username", "email", "password", "passwd", "current_password"
    }:
        return "authentication"
    if any(word in path for word in ("search", "find", "query")) or names & {
        "q", "query", "search", "keyword"
    }:
        return "search"
    if any(word in path for word in ("upload", "attachment", "media")) or any(
        field.get("type") == "file"
        for form in forms for field in form.get("fields", [])
    ):
        return "file-handling"
    if any(word in path for word in ("profile", "comment", "post", "message", "review")) or names & {
        "comment", "content", "message", "bio", "description"
    }:
        return "user-content"
    if forms:
        return "form-workflow"
    return "general"


async def map_site(
    base_url: str,
    *,
    proxy: str | None = None,
    budget: int = 300,
    max_pages: int = 100,
    max_depth: int = 3,
    headless: bool = True,
    _client: TargetClient | None = None,
    _pacer: Pacer | None = None,
    _warm: bool = True,
    storage_state: str | None = None,
    interaction_limit: int = 3,
    progress=None,
) -> SiteMapResult:
    """Map same-origin pages and a bounded set of safe, read-oriented controls."""
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("base_url must be an absolute http:// or https:// URL")
    if budget < 1:
        raise ValueError("budget must be at least 1")
    if max_pages < 1:
        raise ValueError("max_pages must be at least 1")
    if max_depth < 0:
        raise ValueError("max_depth cannot be negative")
    if interaction_limit < 0:
        raise ValueError("interaction_limit cannot be negative")

    normalized_base = urlunsplit((
        parsed.scheme.lower(), parsed.netloc, parsed.path or "/",
        parsed.query, parsed.fragment,
    ))
    origin = f"{parsed.scheme}://{parsed.netloc}"
    result = SiteMapResult(target=normalized_base)
    pacer = _pacer or Pacer(budget=budget)
    owns_client = _client is None
    client = _client or TargetClient(origin, proxy=proxy)
    endpoints_seen: set[tuple[str, str]] = set()
    pages_seen: set[str] = set()
    queued: set[str] = set()
    queue = deque([(normalized_base, 0)])
    group_data: dict[str, BehaviourGroup] = {}

    try:
        if progress:
            progress("[bold cyan]Browser[/bold cyan] Starting Chromium and preparing the scan session")
        if owns_client:
            await client.start(
                oracle_init_script=ORACLE_INIT_JS,
                request_guard=pacer.reserve,
                headless=headless,
                navigation_guard=lambda destination: _is_in_scope(destination, normalized_base),
                request_filter=lambda request: _mapping_request_allowed(
                    request.url, request.resource_type, normalized_base
                ),
                storage_state=storage_state,
            )
        else:
            client.request_guard = pacer.reserve
            client.budget_exhausted = False
        await client.page.add_init_script(_ROUTE_CAPTURE_JS)
        preloaded_key = None
        if _warm:
            if progress:
                progress(f"[dim]Connecting[/dim] Opening the first page {normalized_base}")
            await pacer.pause()
            if not await client.warm(url=normalized_base):
                result.errors.append("Could not reach the application origin.")
                if client.budget_exhausted or pacer.exhausted:
                    result.budget_exhausted = True
                return result
            preloaded_key = _page_key(client.page.url)

        while queue and len(result.pages) < max_pages:
            url, depth = queue.popleft()
            key = _page_key(url)
            if key in pages_seen or not _is_in_scope(url, normalized_base):
                continue
            pages_seen.add(key)
            result.pages_attempted += 1
            if progress:
                progress(f"[cyan]Mapping[/cyan] {url} (depth {depth}, {pacer.used}/{pacer.budget} discovery requests)")
            page_endpoints: list[DiscoveredEndpoint] = []

            capture_tasks = set()
            active_interaction: list[dict] | None = None

            async def capture_request(request, source, trigger):
                request_url = request.url
                if not _is_in_scope(request_url, normalized_base):
                    return
                if request.resource_type not in ("xhr", "fetch"):
                    return
                try:
                    all_headers = await request.all_headers()
                except Exception:
                    all_headers = request.headers
                if _is_framework_navigation_request(
                    request_url, all_headers, request.method
                ):
                    result.framework_requests += 1
                    if progress:
                        progress(
                            f"[dim]Framework navigation[/dim] "
                            f"{request.method.upper()} {urlsplit(request_url).path} "
                            f"(excluded from application API testing)"
                        )
                    return
                endpoint_key = (request.method.upper(), request_url)
                raw_headers = {
                    key.lower(): value for key, value in all_headers.items()
                    if key.lower() in {
                        "content-type", "authorization", "x-csrf-token",
                        "x-xsrf-token", "x-requested-with", "accept",
                    } or key.lower().startswith("x-")
                }
                raw_body = request.post_data
                parsed_body = None
                content_type = raw_headers.get("content-type", "")
                if raw_body and "application/json" in content_type.lower():
                    try:
                        value = json.loads(raw_body)
                        if isinstance(value, dict):
                            parsed_body = value
                    except (ValueError, TypeError):
                        pass
                elif raw_body and "application/x-www-form-urlencoded" in content_type.lower():
                    parsed_body = {
                        key: values[-1]
                        for key, values in parse_qs(raw_body, keep_blank_values=True).items()
                    }
                if endpoint_key in endpoints_seen:
                    existing = next(
                        (item for item in result.endpoints
                         if (item.method, item.url) == endpoint_key), None
                    )
                    if existing and parsed_body:
                        existing.request_body = parsed_body
                        existing.headers.update(raw_headers)
                    if existing and trigger:
                        existing.trigger = trigger
                    return
                endpoints_seen.add(endpoint_key)
                endpoint = DiscoveredEndpoint(
                    url=request_url,
                    method=request.method.upper(),
                    resource_type=request.resource_type,
                    source_page=source,
                    query_parameters=sorted({
                        name for name, _ in parse_qsl(
                            urlsplit(request_url).query, keep_blank_values=True
                        )
                    }),
                    request_body=parsed_body,
                    headers=raw_headers,
                    content_type=content_type,
                    trigger=trigger,
                )
                result.endpoints.append(endpoint)
                page_endpoints.append(endpoint)
                if progress:
                    progress(f"[blue]API observed[/blue] {endpoint.method} {endpoint.url} ({endpoint.resource_type})")

            def record_request(request, source=url):
                trigger_path = list(active_interaction) if active_interaction else None
                task = asyncio.create_task(
                    capture_request(request, source, trigger_path)
                )
                capture_tasks.add(task)
                task.add_done_callback(capture_tasks.discard)
            client.page.on("request", record_request)
            status = None
            try:
                if preloaded_key == key and _page_key(client.page.url) == key:
                    # The reachability check already loaded the first target;
                    # reuse it instead of downloading the homepage twice.
                    status = client.last_response_status
                    preloaded_key = None
                else:
                    await pacer.pause()
                    response = await client.page.goto(
                        url, wait_until="domcontentloaded", timeout=20000
                    )
                    status = response.status if response else None
                final_url = client.page.url
                if progress:
                    progress(f"[dim]HTTP response[/dim] {status if status is not None else 'no status'} — {final_url}")
                if not _is_in_scope(final_url, normalized_base):
                    result.errors.append(
                        f"{url}: navigation ended outside the allowed origin"
                    )
                    continue
                final_key = _page_key(final_url)
                if final_key in pages_seen and final_key != key:
                    continue
                url = final_url
                pages_seen.add(final_key)
                try:
                    await client.page.wait_for_load_state("networkidle", timeout=1500)
                except Exception:
                    pass
                if capture_tasks:
                    await asyncio.gather(*tuple(capture_tasks), return_exceptions=True)
                if progress:
                    progress("[dim]Inspecting page[/dim] Reading title, forms, links, and browser activity")
                title = await client.page.title()
                forms_raw = await discover_forms(client.page)
                forms = [
                    {
                        "action": form.action,
                        "method": form.method,
                        "enctype": form.enctype,
                        "fields": [
                            {"name": item.name, "type": item.type, "role": item.role.value}
                            for item in form.fields
                        ],
                    }
                    for form in forms_raw
                ]
                discovered_links = await client.page.evaluate(
                    "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
                )

                # Queue ordinary same-origin navigation before spending requests
                # on optional UI exploration. Reserve an allowance for the
                # remaining page visits, capped by max_pages.
                links: list[str] = []
                for raw_link in discovered_links or []:
                    absolute = urljoin(url, raw_link)
                    if not _is_in_scope(absolute, normalized_base):
                        continue
                    link_key = _page_key(absolute)
                    if link_key not in pages_seen and link_key not in queued and depth < max_depth:
                        queued.add(link_key)
                        queue.append((absolute, depth + 1))

                page_slots_left = max(0, max_pages - len(result.pages) - 1)
                reserved_page_requests = min(
                    pacer.remaining,
                    min(len(queue), page_slots_left) * 18,
                )
                interaction_allowance = max(0, pacer.remaining - reserved_page_requests)
                explore_interactions = (
                    interaction_limit > 0 and interaction_allowance >= 8
                )
                if progress and interaction_limit and not explore_interactions:
                    progress(
                        f"[dim]UI exploration deferred[/dim] "
                        f"{len(queue)} page(s) queued; preserving "
                        f"{reserved_page_requests} discovery requests for page coverage"
                    )

                if progress:
                    progress(f"[dim]Page analysis[/dim] {title[:70]!r}: {len(forms)} forms, {len(discovered_links)} links, {len(page_endpoints)} API calls observed")

                # Explore a bounded set of non-submit controls. Forms, ordinary
                # links, and controls with state-changing labels are excluded.
                if explore_interactions:
                    interaction_path: list[dict] = []
                    seen_interactions: set[tuple[str, str, int]] = set()
                    # Re-scan the DOM after each action. This reveals controls
                    # that only become available after an earlier safe action.
                    for _ in range(interaction_limit):
                        controls = await client.page.evaluate(_INTERACTION_CANDIDATES_JS)
                        control = next((
                            item for item in controls
                            if (
                                item["role"], item["name"], item["match_index"]
                            ) not in seen_interactions
                        ), None)
                        if control is None:
                            break
                        identity = (
                            control["role"], control["name"], control["match_index"]
                        )
                        seen_interactions.add(identity)
                        step = {
                            "role": control["role"],
                            "name": control["name"],
                            "match_index": control["match_index"],
                        }
                        interaction_path.append(step)
                        active_interaction = list(interaction_path)
                        if progress:
                            progress(f"[magenta]UI step {result.interactions_attempted + 1}[/magenta] Trying {control['role']} {control['name']!r} on {url}")
                        try:
                            locator = client.page.get_by_role(
                                control["role"], name=control["name"], exact=True
                            )
                            if await locator.count() <= control["match_index"]:
                                continue
                            await locator.nth(control["match_index"]).click(timeout=1500)
                            result.interactions_attempted += 1
                            if progress:
                                progress(f"[green]UI step complete[/green] {control['name']!r}; checking for new routes and API activity")
                            try:
                                await client.page.wait_for_load_state(
                                    "networkidle", timeout=1000
                                )
                            except Exception:
                                pass
                            if capture_tasks:
                                await asyncio.gather(
                                    *tuple(capture_tasks), return_exceptions=True
                                )
                            if not _is_in_scope(client.page.url, normalized_base):
                                result.errors.append(
                                    f"{url}: UI interaction attempted an out-of-scope navigation"
                                )
                                break
                        except BudgetExhausted:
                            result.budget_exhausted = True
                            if progress:
                                progress(f"[yellow]Discovery budget reached[/yellow] while exploring {control.get('name', '')!r}; keeping the page discovery already collected")
                            break
                        except Exception as exc:
                            result.errors.append(
                                f"{url}: UI control {control.get('name', '')!r}: "
                                f"{type(exc).__name__}: {str(exc)[:120]}"
                            )
                            break
                        finally:
                            active_interaction = None

                observed_routes = await client.page.evaluate(
                    "() => window.__hx_routes || []"
                )
                discovered_links.extend(observed_routes or [])
                discovered_links.extend(await client.page.evaluate(
                    "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
                ))
            except BudgetExhausted:
                result.budget_exhausted = True
                result.pages_pending.append(url)
                if progress:
                    progress(f"[yellow]Discovery budget exhausted[/yellow] while processing {url}")
                break
            except Exception as exc:
                if client.budget_exhausted or pacer.exhausted:
                    result.budget_exhausted = True
                    result.pages_pending.append(url)
                    if progress:
                        progress(f"[yellow]Page deferred[/yellow] {url} — discovery budget exhausted during navigation")
                    break
                result.pages_failed.append(url)
                result.errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:180]}")
                continue
            finally:
                try:
                    client.page.remove_listener("request", record_request)
                except Exception:
                    pass

            # Include routes and links revealed by safe UI exploration. The
            # initial anchors were already queued before interactions.
            for raw_link in discovered_links or []:
                absolute = urljoin(url, raw_link)
                if not _is_in_scope(absolute, normalized_base):
                    continue
                link_key = _page_key(absolute)
                if link_key not in pages_seen and link_key not in queued and depth < max_depth:
                    queued.add(link_key)
                    queue.append((absolute, depth + 1))
                if absolute not in links:
                    links.append(absolute)

            query_names = sorted({
                name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            })
            fragment = urlsplit(url).fragment
            if "?" in fragment:
                query_names.extend(
                    name for name, _ in parse_qsl(fragment.split("?", 1)[1], keep_blank_values=True)
                )
            elif "=" in fragment or "&" in fragment:
                query_names.extend(name for name, _ in parse_qsl(fragment, keep_blank_values=True))
            query_names = sorted(set(query_names))
            behaviour = _behaviour_for(url, forms)
            result.pages.append(DiscoveredPage(
                url=url, depth=depth, title=title or "", status=status,
                links=sorted(set(links)), query_parameters=query_names,
                forms=forms, behaviour=behaviour,
            ))

            if progress:
                progress(f"[green]Page mapped[/green] {url} — {len(forms)} forms, {len(page_endpoints)} API endpoints, {len(links)} same-origin links queued ({len(queue)} pending); requests {pacer.used}/{pacer.budget}")
            group = group_data.setdefault(behaviour, BehaviourGroup(name=behaviour))
            group.pages.append(url)
            for form in forms:
                signature = form["method"] + " " + form["action"] + " [" + ",".join(
                    field["name"] for field in form["fields"] if field["role"] == "injectable"
                ) + "]"
                if signature not in group.form_signatures:
                    group.form_signatures.append(signature)
            for endpoint in page_endpoints:
                if endpoint.url not in group.endpoint_urls:
                    group.endpoint_urls.append(endpoint.url)

            if client.budget_exhausted:
                result.budget_exhausted = True
                break

    except BudgetExhausted:
        result.budget_exhausted = True
    finally:
        result.requests_used = pacer.used
        result.budget_exhausted = result.budget_exhausted or pacer.exhausted or client.budget_exhausted
        if owns_client:
            await client.close()

    result.pages_pending = list(dict.fromkeys(
        [*result.pages_pending, *(pending_url for pending_url, _ in queue)]
    ))
    result.groups = sorted(group_data.values(), key=lambda group: group.name)
    if progress:
        progress(
            f"[cyan]Discovery finished[/cyan]: {len(result.pages)} mapped, "
            f"{result.pages_attempted} attempted, {len(result.pages_failed)} failed, "
            f"{len(result.pages_pending)} pending; {len(result.endpoints)} application "
            f"endpoints, {result.framework_requests} framework requests; "
            f"{pacer.used}/{pacer.budget} requests"
        )
    return result

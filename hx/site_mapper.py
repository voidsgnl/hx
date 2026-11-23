"""Read-only, same-origin website mapping for automated scan planning.

The mapper discovers rendered routes, forms, and browser-observed API calls.
It never submits forms or sends vulnerability payloads.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

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
    budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

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
) -> SiteMapResult:
    """Map a website using read-only browser navigation within one origin."""
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("base_url must be an absolute http:// or https:// URL")
    if budget < 1:
        raise ValueError("budget must be at least 1")
    if max_pages < 1:
        raise ValueError("max_pages must be at least 1")
    if max_depth < 0:
        raise ValueError("max_depth cannot be negative")

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
        if owns_client:
            await client.start(
                oracle_init_script=ORACLE_INIT_JS,
                request_guard=pacer.reserve,
                headless=headless,
                navigation_guard=lambda destination: _is_in_scope(destination, normalized_base),
            )
        else:
            client.request_guard = pacer.reserve
            client.budget_exhausted = False
        await client.page.add_init_script(_ROUTE_CAPTURE_JS)
        if _warm:
            await pacer.pause()
            if not await client.warm():
                result.errors.append("Could not reach the application origin.")
                return result

        while queue and len(result.pages) < max_pages:
            url, depth = queue.popleft()
            key = _page_key(url)
            if key in pages_seen or not _is_in_scope(url, normalized_base):
                continue
            pages_seen.add(key)
            page_endpoints: list[DiscoveredEndpoint] = []

            def record_request(request, source=url):
                request_url = request.url
                if not _is_in_scope(request_url, normalized_base):
                    return
                if request.resource_type not in ("xhr", "fetch"):
                    return
                endpoint_key = (request.method.upper(), request_url)
                if endpoint_key in endpoints_seen:
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
                )
                result.endpoints.append(endpoint)
                page_endpoints.append(endpoint)

            client.page.on("request", record_request)
            status = None
            try:
                await pacer.pause()
                response = await client.page.goto(
                    url, wait_until="domcontentloaded", timeout=20000
                )
                status = response.status if response else None
                final_url = client.page.url
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
                observed_routes = await client.page.evaluate(
                    "() => window.__hx_routes || []"
                )
                discovered_links.extend(observed_routes or [])
            except BudgetExhausted:
                result.budget_exhausted = True
                break
            except Exception as exc:
                result.errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:180]}")
                continue
            finally:
                try:
                    client.page.remove_listener("request", record_request)
                except Exception:
                    pass

            links: list[str] = []
            for raw_link in discovered_links or []:
                absolute = urljoin(url, raw_link)
                if not _is_in_scope(absolute, normalized_base):
                    continue
                link_key = _page_key(absolute)
                if link_key not in pages_seen and link_key not in queued and depth < max_depth:
                    queued.add(link_key)
                    queue.append((absolute, depth + 1))
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

    result.groups = sorted(group_data.values(), key=lambda group: group.name)
    return result

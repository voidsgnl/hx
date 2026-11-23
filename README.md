# hx

**hx** is an execution-oracle XSS scanner. It looks for reflected input, selects
payloads based on the reflection context, and uses a real Chromium browser to
check whether a payload actually executes.

A reflected string is only a candidate. **hx reports a proven XSS finding only
when its browser oracle observes the proof marker belonging to the exact
payload being tested.** A reflection by itself is not a vulnerability finding.

> hx is an early-stage security testing tool (version 0.1.0). Use it only on
> applications you own or have explicit permission to test.

## How it works

The scan pipeline has three main stages:

1. **FastPath discovery** — sends a small marker through the supplied input and
   checks whether the application reflects it. This uses `curl_cffi` for the
   HTTP fast path.
2. **Context analysis and payload selection** — inspects where the marker
   appears (for example, HTML text or an attribute) and chooses payloads for
   that context.
3. **Browser execution oracle** — opens the candidate in Chromium and checks
   for execution evidence associated with that payload's unique ID. Every hit
   records the document origin, and proof is accepted only when execution
   occurs in the origin explicitly targeted by that probe.
4. **Differential control** — when an active payload executes, hx repeats the
   same injection shape with only the proof callback replaced by a benign
   no-op. A finding is marked `proven_execution` only when the active probe
   executes and the control does not. If the request budget prevents the
   control from running, the result is retained as
   `executed_without_control`, not silently promoted to differential proof.

Website mode uses a separate discovery and planning path before invoking
vulnerability engines:

1. **Website mapper** — follows same-origin pages and JavaScript-driven routes,
   records forms, and observes same-origin fetch/XHR endpoints.
2. **Behaviour analysis** — groups pages into surfaces such as authentication,
   search, user content, file handling, and general form workflows.
3. **Engine registry** — selects independent vulnerability engines for each
   discovered input surface.
4. **Verification** — each engine applies its own evidence requirements. The
   currently implemented engines are XSS and open redirect. XSS uses the
   Chromium execution oracle; open redirect checks HTTP Location headers.

This structure lets hx add vulnerability classes without coupling their
payloads or verification rules to the crawler.

The distinction matters:

| Result | Meaning |
| --- | --- |
| Reflection | The application returned or rendered the marker. This is not proof of XSS. |
| Differentially proven finding | The active payload produced its exact proof event in the target origin; the paired benign control did not. |
| Executed without control | The active payload executed, but the paired control could not complete (for example, because the request budget was exhausted). |

For GET URLs, hx also checks query parameters embedded in client-side URL
fragments (for example, `/#/search?q=test`). Fragments are inspected in the
browser because browsers do not send them to the server in HTTP requests.

## Features

- GET query-parameter reflection discovery.
- Form-encoded POST and JSON POST input testing.
- Browser-side inspection of client-side fragment parameters.
- Context-aware payload selection.
- Chromium-based JavaScript execution verification.
- Unique payload IDs and origin-scoped proof events to associate execution with the exact probe and target origin.
- Differential A/B verification using a syntax-preserving benign control payload.
- Per-scan outbound request budget and jittered pacing.
- Optional proxy support.
- Headless mode by default, with an optional visible browser.
- Read-only HTML form discovery with text and JSON output.
- Automatic same-origin website mapping and XSS testing of discovered GET inputs.
- Behaviour grouping for authentication, search, user-content, file-handling, and form workflows.
- Discovery of browser-observed same-origin fetch/XHR endpoints.
- JSON scan output for scripting and further analysis.

## Requirements

- Python 3.11 or newer.
- A supported Linux, macOS, or Windows environment for Playwright.
- Chromium installed through Playwright.
- Network access to the target application.

The project pins Playwright and curl-cffi together. Their browser and
impersonation profiles are intended to use the same Chrome major version.
Changing only one dependency can create a fingerprint mismatch and cause
unexpected target responses.

Current pinned pair:

- `playwright==1.62.0` (bundled Chromium major 151)
- `curl_cffi==0.17.0` (impersonation profile `chrome151`)

## Installation

Clone the repository and enter it:

```bash
git clone https://github.com/voidsgnl/hx.git
cd hx
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the exact dependency set recorded in the lock file, then install hx
itself in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
```

Install the Playwright Chromium browser:

```bash
python -m playwright install chromium
```

On Linux, if Playwright reports missing operating-system libraries, install
the browser dependencies as well:

```bash
python -m playwright install --with-deps chromium
```

Check the installation:

```bash
hx version
hx --help
hx scan --help
hx discover --help
hx session --help
```

If you prefer pip to resolve the development dependencies rather than use the
committed lock file, install with:

```bash
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

## Usage

Only scan systems that you are authorized to assess. Start with a local test
application or a deliberately vulnerable lab.

### Map a website without active testing

Use `map` when you only want to inventory the site's same-origin pages,
forms, behaviour groups, and browser-observed fetch/XHR endpoints:

```bash
hx map "http://localhost:5000/" --max-pages 100 --max-depth 3
hx map "http://localhost:5000/" --json
hx map "https://app.example.com/" --storage-state .hx/session.json
```

This operation does not inject payloads or submit forms.

### Automatically scan a website

When the URL has no query input and no POST body, `hx scan` selects website
mode automatically:

```bash
hx scan "http://localhost:5000/"
```

Website mode maps same-origin pages, groups them by observable behaviour, then
runs the applicable registered engines against discovered GET inputs. The
current engines check XSS and recognized open-redirect parameters. Control
discovery size with:

```bash
hx scan "http://localhost:5000/" --max-pages 50 --max-depth 3 --budget 300
```

Choose the mode explicitly when needed:

```bash
hx scan "http://localhost:5000/" --mode website
hx scan "http://localhost:5000/reflect" --mode target
```

The explicit target mode preserves direct testing of paths without query
strings. POST forms are discovered but remain passive unless you explicitly
enable active POST testing.

### Authenticated POST form testing

Capture an authenticated browser session first:

```bash
hx session "https://app.example.com/login" --output .hx/session.json
```

Chromium opens visibly. Log in normally, return to the terminal, and press
Enter. hx saves the browser cookies and localStorage as a Playwright storage
state file with owner-only permissions.

Use that state for a website scan:

```bash
hx scan "https://app.example.com/" \\
  --storage-state .hx/session.json \\
  --active-post \\
  --budget 500
```

Active POST testing reloads each source form in the same authenticated browser
context before each probe. That preserves current hidden fields (including
ordinary hidden CSRF tokens), cookies, and normal form submission handlers.
Authentication forms are excluded by default. To include them, add
`--include-auth-forms`; this can trigger account lockouts or alter login
state. Password and file inputs are never selected as injection parameters,
and file-upload forms are not actively submitted.

**Important:** active POST testing submits real application forms and can
change server-side state. Use it only on systems and accounts you are
authorized to test, preferably in a staging environment. It currently covers
HTML POST forms, not browser-observed POST API endpoints. Applications that
depend on sessionStorage or custom JavaScript-only CSRF headers may need
additional session/request integration.

### Current vulnerability engines

- **XSS** — reflected input discovery followed by payload-specific browser
  execution verification. Supports explicit GET/POST/JSON targets and
  opt-in website-discovered HTML POST forms.
- **Open redirect** — tests recognized redirect parameters with a reserved
  `.invalid` canary and verifies the HTTP `Location` header without following
  the external redirect.

SQL injection, SSRF, authentication-logic, and file-upload vulnerability
engines are not implemented yet. The engine registry is the extension point
for adding their own detection and verification logic.

### Scan a GET URL

Provide a URL containing one or more query parameters:

```bash
hx scan "http://localhost:5000/reflect?q=test"
```

### Scan form-encoded POST data

Provide the endpoint and the form fields to test:

```bash
hx scan "http://localhost:5000/reflect" --data "q=test"
```

### Scan a JSON POST body

Provide a JSON object:

```bash
hx scan "http://localhost:5000/api/search" --json-body '{"q":"test"}'
```

`--data` and `--json-body` are mutually exclusive. If neither is supplied,
hx scans the query parameters in the URL as a GET request.

### Use a proxy

Pass a proxy URL with `--proxy`:

```bash
hx scan "http://localhost:5000/reflect?q=test" \
  --proxy "http://127.0.0.1:8080"
```

### Show the Chromium browser

Scans are headless by default. Add `--headed` to display Chromium:

```bash
hx scan "http://localhost:5000/reflect?q=test" --headed
```

### Set a request budget

The default budget is 120 outbound HTTP requests per scan. Use `--budget` to
set a lower or higher limit:

```bash
hx scan "http://localhost:5000/reflect?q=test" --budget 30
```

The budget is a safety limit, not a target for how many requests a scan should
make. When it is exhausted, hx stops the scan and reports that the budget was
exhausted.

### Emit JSON

Use `--json` for machine-readable output:

```bash
hx scan "http://localhost:5000/reflect?q=test" --json
```

The scan JSON includes:

- `target` and `reached_app`
- `requests_used` and `budget_exhausted`
- Browser/HTTP fingerprint comparison
- `reflections` — reflected marker candidates
- `findings` — browser-proven findings, including context, payload ID,
  confidence tier, active execution-hit evidence, and benign-control evidence
  when the control completed

A scan can return reflections and still have an empty `findings` list. That
means hx saw the input reflected but did not prove JavaScript execution.

## Read-only form discovery

Use `discover` to inspect forms on a page:

```bash
hx discover "http://localhost:5000/login"
```

JSON output:

```bash
hx discover "http://localhost:5000/login" --json
hx discover "https://app.example.com/profile" --storage-state .hx/session.json
```

Visible browser:

```bash
hx discover "http://localhost:5000/login" --headed
```

Discovery reports form action, method, encoding type, and field names/types.
Fields are classified as:

- **injectable** — enabled, named, text-like input fields.
- **static** — hidden fields and fields whose names look token-related.
- **skip** — disabled or unnamed fields and controls such as submit, button,
  reset, image, and file inputs.

This operation is deliberately read-only: it does not submit forms, change
account state, or run XSS payloads. It is a discovery aid, not automatic form
scanning. To scan a form, construct an explicit GET, `--data`, or
`--json-body` request yourself.

## Understanding the output

- **Could not reach application** — the browser warm-up did not reach the
  application successfully. A challenge page, network problem, or other
  access restriction may be responsible.
- **Fingerprint warning** — the browser's Chrome major version and the
  curl-cffi impersonation profile do not match. Treat results cautiously.
- **Reflections found** — input markers were reflected. Reflection alone does
  not demonstrate that the input is executable.
- **No proven XSS** — no tested candidate produced the expected browser proof.
  This does not prove the application is free of XSS.
- **Proven XSS** — the browser oracle observed execution evidence associated
  with the tested payload ID.

The browser instrumentation is diagnostic and can be detected or interfered
with by target-side JavaScript. The proof mechanism reduces accidental
misattribution; it is not a cryptographic guarantee against a deliberately
hostile page.

## Development and tests

Install the project with development dependencies:

```bash
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

Run the test suite:

```bash
python -m pytest -q
```

Run a focused test module:

```bash
python -m pytest tests/test_oracle.py -v
```

The tests include a local Flask harness for controlled reflection and
execution cases. They are intended for development and regression testing,
not for testing against third-party systems.

GitHub Actions runs the test suite on pushes to `main` and pull requests.

### Updating the browser fingerprint pair

Do not upgrade Playwright or curl-cffi independently. Check the Chromium major
version bundled by Playwright and the matching impersonation profiles
available in curl-cffi, then update `pyproject.toml`, `hx/versions.py`, and
the lock file together.

Run the fingerprint regression test after an intentional update:

```bash
python -m pytest tests/test_fingerprint.py -v
```

The current pair is documented above because Playwright 1.62.0 bundles
Chromium 151, while the available curl-cffi profile includes `chrome151`.
Re-check this compatibility when either dependency is upgraded.

## Current limitations

hx is intentionally a focused scanner, not a general web crawler or
comprehensive application security testing suite.

- Website mode tests discovered GET inputs with the XSS and
  open-redirect engines. Active POST testing currently covers HTML forms only;
  POST API endpoints and other vulnerability classes are not actively tested.
- The separate `discover` command is read-only and never submits forms.
- Reflection and context detection are heuristics. A reflection may be
  harmless, and a real vulnerability may not be reflected in a way hx
  currently recognizes.
- The browser oracle can only prove executions reached by the payloads and
  paths that hx tests. A clean result is not a guarantee that no XSS exists.
- JavaScript-heavy applications, authentication flows, unusual content
  policies, and application-specific request formats may need manual setup
  or further testing.
- Fingerprint matching is a compatibility check; it does not guarantee
  Cloudflare clearance, WAF evasion, or access to a protected application.
- The full proof pipeline has been exercised with the project's local test
  harness. Real-application coverage remains limited; see
  [VALIDATION.md](VALIDATION.md) for the recorded Juice Shop checks and
  outstanding validation gaps.

## Responsible use

Only use hx against systems you own or have explicit permission to test.
Scanning can generate requests, trigger security monitoring, or affect
application behavior. Use a conservative request budget, coordinate testing
with the system owner, and stop if the target becomes unstable or begins
blocking requests.

Do not use hx to access data, accounts, or systems without authorization.

## License

No license is currently declared in the project metadata. Check with the
repository owner before redistributing or incorporating hx into another
project.


### Authenticated JSON POST API testing

The mapper records same-origin fetch/XHR requests, including JSON request bodies and application headers. API replay is separate from HTML form submission because POST APIs can mutate server state.

```bash
hx scan "https://app.example.com/" \
  --storage-state .hx/session.json \
  --active-api \
  --budget 500
```

`--active-api` currently tests same-origin JSON POST endpoints with at least one non-secret scalar body field. It reuses captured Authorization and custom X-* headers (including CSRF headers) plus live browser cookies. Password, token, secret, credential, and CSRF body fields are retained as request context but are not selected as injection parameters. Unsupported content types and bodies that cannot be parsed as JSON are mapped but not actively tested.

Captured Authorization, cookie, token, secret, and credential values are redacted from JSON map/report output. They remain available in memory for request replay. This initial API implementation does not replay multipart, binary, GraphQL-variable, nested JSON, or other non-JSON bodies, and does not invent fields the browser did not send. Enable active API testing only on systems and accounts you are authorized to test, preferably in staging.

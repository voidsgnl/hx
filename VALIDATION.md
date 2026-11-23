# Real application validation

## Scope

Validate `hx` against the locally running OWASP Juice Shop at
`http://localhost:3000/`. This is an exploratory check of discovery,
reflection triage, browser proof, and request pacing. The test target is local
and controlled by the project owner. No broad crawling or production targets
are in scope.

## Predictions to check

| Area | Prediction | Evidence to collect |
| --- | --- | --- |
| SPA form discovery | `discover_forms()` reads `document.forms` immediately after `domcontentloaded`; forms rendered later by Angular may be missing. | Compare `hx discover` output for `/#/` and `/#/login` with forms visible after the UI settles. |
| Form semantics | Read-only discovery reports HTML form fields but does not currently preserve their values or create scan requests. | Compare action, method, field names, and hidden fields with the live DOM. |
| Scan entry point | `hx scan` accepts a URL or explicit GET/form/JSON inputs; it does not scan forms discovered from the SPA. | Confirm that the CLI cannot scan a discovered Juice Shop form without manually constructing a request. |
| Reflection and proof | A marker reflection is only a candidate; only a matching browser execution hit should become a finding. | For any candidate, inspect JSON output for a finding with a payload ID and a matching execution hit. Treat reflection alone as no proof. |
| Pacing accounting | `requests_used` counts calls to `pacer.wait()`, not every HTTP transaction. The candidate body fetch adds an extra fast-path request without another wait; POST proof helpers may also make setup requests. | Compare reported count with local server/browser network logs for a bounded scan. Record any request made without its own pacing slot. |
| Stop on blocks | The current scan orchestration does not stop a form or target after a 403. | If Juice Shop returns a block response, stop the check and record behavior; do not keep probing to exhaust the budget. |
| Cloudflare | No Cloudflare behavior is established by Juice Shop. Matching browser and curl impersonation versions only verifies the configured fingerprint pair. | Leave clearance-cookie and behavioral-validation claims unverified until tested against an owned Cloudflare-fronted target. |
| JSON response semantics | JSON POST proof uses `fetch()` followed by `document.write()`, not native response navigation. | Record any behavior depending on response URL, relative links, or response CSP as out of scope for this check. |

## Procedure

1. Confirm Juice Shop is reachable at `http://localhost:3000/`.
2. Run `hx discover` on `/` and `/#/login`. Compare the output with the forms
   visible after the app settles in a browser.
3. Use only a small, known input and a low request budget for any scan. Capture
   the JSON output and the browser/network request count. Stop if the app begins
   returning 403 or other challenge responses.
4. Check the negative control behavior locally before treating any reflection
   as a finding: only browser execution tagged with the active payload ID counts.
5. Fill in the results below. Keep this report limited to observed behavior;
   do not infer Cloudflare compatibility from this local target.

## Results

Run on 2026-11-22 against the locally hosted Juice Shop at `localhost:3000`.

- `hx discover 'http://localhost:3000/#/' --json` returned `[]`.
- `hx discover 'http://localhost:3000/#/login' --json` found one rendered
  Angular form: GET route `/#/login`, fields `ng.form0.email` and
  `ng.form0.password` classified injectable, and `ng.form0.rememberMe`
  classified static. The login form was not submitted. These results show
  route-dependent discovery; they do not by themselves prove that a settle
  poll is required, since there was no delayed-DOM comparison.
- Initial `curl_cffi` diagnosis against
  `/rest/products/search?q=test`:
  - `impersonate="chrome151"` failed with `Empty reply from server`, with
    redirects both disabled and enabled.
  - `impersonate=None` returned status 200 and a 744-byte response, with
    redirects both disabled and enabled.
  - For Chrome impersonation, `http_version="v1"` returned status 200 and
    the 744-byte response. `v2` failed; `v2tls` and `v3` returned status 200.
  - Verbose plain `curl` confirmed this is the correct route: HTTP/1.1 200,
    JSON content type, 744-byte body. `/rest/products` returned an Express
    unexpected-path page.
- Added `test_chrome_impersonation_can_fetch_juice_shop_http_response` in
  `tests/harness/test_fastpath.py`. It skips with an explicit reason when the
  local Juice Shop is unavailable. The test failed against the old FastPath
  and passed after setting `http_version="v1"` for all FastPath GET and POST
  calls. A generic Python HTTP/1.1 server did not reproduce the failure, so
  the regression uses the running Node service that exposed it.
- Bounded scan after the fix:
  `hx scan 'http://localhost:3000/rest/products/search?q=test' --json --budget 20`
  returned `reached_app=true`, `requests_used=2`,
  `budget_exhausted=false`, and matching browser/impersonation versions 151.
  It found no candidate reflections and no findings; context classification
  and oracle proof were therefore not exercised on Juice Shop. There was no
  403 or block response.
- The reported count of 2 matches the two `pacer.wait()` calls expected for
  this no-candidate scan: one before `warm()` and one before the fast-path
  parameter request. This is the scanner's logical count, not a count of
  browser subresource requests. The test does not validate pacing against a
  rate-limiting target.
- Full suite after the change: `29 passed in 64.74s`, including the new
  Juice Shop regression and the existing oracle positive/negative controls.
- The Cloudflare prediction remains untested. No blocking response was
  observed during the discovery requests.

### Real DOM proof-pipeline attempt

- Ran
  `hx scan 'http://localhost:3000/#/search?q=test' --json --budget 20`.
  Output: `reached_app=true`, `requests_used=1`, `budget_exhausted=false`,
  `reflections=[]`, `findings=[]`; browser and impersonation versions both
  matched at 151.
- The single pacing slot was the initial `warm()` navigation. `scan()` reads
  parameters from `urlparse(url).query`; here `q=test` is inside the URL
  fragment, so no parameter was selected and the fast path, context detector,
  and execution oracle were not reached.
- Separately opened the route in Chromium with harmless marker
  `hxdomcheckmarker`. The rendered body contained `Search Results -
  hxdomcheckmarker` and `No results found`. This confirms client-side text
  reflection, but does not establish XSS or validate the scanner's proof
  pipeline.
- Repeated the scan for the supplied URL
  `http://localhost:3000/#/search?q=hi`: it again used one request and
  returned no reflections or findings. Chromium showed `Search Results - hi`
  in the page body; `No results found` was absent for this value.
- Checked the DVWA path on localhost ports 80, 8080, and 4280; all refused the
  connection. No DVWA scan was run.
- Conclusion: proof and context classification against a real reflected-XSS
  sink remain unvalidated. Juice Shop reflects this value client-side, but
  the scanner currently does not extract fragment parameters; the DVWA
  fallback was unavailable at the checked local addresses. The Flask harness
  remains the only target on which the full proof pipeline has been
  demonstrated.

### Request-accounting follow-up

- `TargetClient` always installs its browser request route. If a request
  reaches that route without `request_guard`, the client increments
  `requests_unaccounted`; `scan()` snapshots that counter and installs the
  current scan's `pacer.reserve` before making scan requests, including when
  the client was pre-started and injected through `_client`.
- `coverage.requests_unaccounted` is the client counter delta during the
  scan, not a constant. `test_unaccounted_is_measured_not_assigned` verifies
  both a normal shared-client scan reports zero and a deliberately
  guard-disabled request during a scan is reported as nonzero.

### Authenticated request-state regression (2026-11-23)

- Added `/authed-reflect`, which returns an unescaped reflection only when
  `X-Test-Auth: secret` is present, and `/authed-cookie-reflect` for the
  equivalent cookie check.
- Before the implementation change, the authenticated-header test failed:

  ```text
  tests/test_auth_request_spec.py::test_authed_scan_proves_end_to_end FAILED
  tests/test_auth_request_spec.py::test_authed_scan_without_header_does_not_prove PASSED
  AssertionError: assert 0 == 1
  ScanResult(... reached_app=True, reflections=[], findings=[], requests_used=2,
             coverage.params_tested=1, coverage.reflections=0 ...)
  1 failed, 1 passed in 11.34s
  ```

  The harness returned 401 and FastPath found no reflection, so the browser
  oracle was never reached. On this exact baseline both consumers omitted
  `RequestSpec.headers`; this demonstrated the request-state false-negative
  class but did not isolate a browser-only divergence.
- `RequestSpec.headers` and `RequestSpec.cookies` are now the shared request
  state. `_apply_marker()` copies the full spec, FastPath receives both on
  GET and POST requests, and the browser context installs headers and cookies
  before its first navigation. `storage_state` is still loaded; an explicit
  spec cookie replaces a conflicting state cookie and logs at debug level.
  The FastPath merges explicit cookies over browser cookies and recalculates
  cookie scope at each redirect. Header values are also withheld on
  third-party redirects.
- curl_cffi treats a bare cookie mapping for `localhost` as `localhost.local`
  in this environment. FastPath now binds those cookies to the actual
  `localhost` host; this was verified against the cookie-authenticated harness
  endpoint.
- The CLI accepts repeatable `--header` / `-H` and `--cookie` options in
  target mode. `--cookie` values override same-name cookies from a `Cookie`
  header, and malformed values raise `BadParameter`. The no-header control
  reports the 401 in coverage instead of presenting it as a clean scan.
- After the fix, the header and cookie end-to-end scans both produced
  browser-proven findings; the no-header control produced no finding and
  recorded `GET /authed-reflect -> 401`.
- Full suite after these changes: `129 passed, 2 skipped in 335.09s`.
- The CLI now accepts a DVWA session via `--cookie` or `--header`, removing
  the tool-side auth-input gap. DVWA itself was not available on the local
  ports checked earlier, so access and proof against DVWA remain unvalidated.

### Authenticated bWAPP scan (2026-11-23)

- Ran a bounded scan against the locally hosted bWAPP GET XSS page at
  `http://localhost:4281/xss_get.php` with a supplied session cookie, a
  budget of 120, and JSON output saved to `/tmp/bwapp-scan.json`. The cookie
  value is intentionally omitted from this report.
- The scan reached the application and used 79 requests; the budget was not
  exhausted. Browser and FastPath fingerprints both reported Chromium 151,
  with `matches=true`.
- Coverage reported three parameters discovered and tested, two reflections,
  zero blocked requests, and zero unaccounted requests. The scanner reported
  two browser-proven findings, for `firstname` and `lastname`; each proof hit
  carried the target origin `http://localhost:4281`.
- The JSON output was successfully parsed with `python -m json.tool`.


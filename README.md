## Version pinning (WAF resistance)

`hx` relies on Playwright Chromium and curl-cffi sharing the same Chrome major
version so browser-earned `cf_clearance` cookies remain valid in the fast path.

The pinned pair is declared in `pyproject.toml` and
`hx/versions.py`:

- `playwright==1.62.0`
- `curl_cffi==0.17.0`
- Chromium 151 / `chrome151`

`curl_cffi==0.17.0` also ships a `chrome152` profile, but no published
Playwright release currently bundles Chromium 152: Playwright 1.62.0 bundles
151 and 1.63.0 bundles 153. The pinned pair therefore uses the exact available
151 match rather than an unsupported or mismatched profile.

Install the exact dependency graph from the committed lock:

```bash
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
```

The lock includes the development dependencies used by tests. To intentionally
refresh it, install pip-tools and run
`pip-compile --extra=dev --resolver=backtracking --generate-hashes -o requirements.lock pyproject.toml`.

Upgrade both dependencies together and run
`pytest tests/test_fingerprint.py -v`. Never upgrade one without the other:
fingerprint drift produces silent 403 responses on Cloudflare-style targets.

## Read-only form discovery

List forms and field metadata on a page without submitting any form:

```bash
hx discover "http://localhost:5000/discovery"
hx discover "http://localhost:5000/discovery" --json
```

Text-like controls are labeled injectable; hidden fields and token-like names
are labeled static; disabled controls, buttons, and file inputs are skipped.
Field values are not included in output. This command only inspects the page;
it does not submit forms or run payloads.
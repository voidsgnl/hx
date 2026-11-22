## Version pinning (WAF resistance)

`hx` relies on Playwright Chromium and curl-cffi sharing the same Chrome major
version so browser-earned `cf_clearance` cookies remain valid in the fast path.

The pinned pair is declared in `pyproject.toml` and
`hx/versions.py`:

- `playwright==1.49.1`
- `curl_cffi==0.17.0`
- Chromium 131 / `chrome131`

Upgrade both dependencies together and run
`pytest tests/test_fingerprint.py -v`. Never upgrade one without the other:
fingerprint drift produces silent 403 responses on Cloudflare-style targets.
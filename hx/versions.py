"""Pinned browser/fast-path versions; change both together.

Playwright 1.62.0 bundles Chromium 151. curl_cffi 0.17.0 supports chrome151
and chrome152, but rejects chrome153. Playwright jumps from Chromium 151 to
153, so 151 is the highest matching profile available today. Re-check this
constraint on upgrades; see README.md and run tests/test_fingerprint.py.
"""

CHROMIUM_MAJOR = "151"
CURL_CFFI_IMPERSONATE = "chrome151"

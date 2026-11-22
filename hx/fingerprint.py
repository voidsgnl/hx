"""Fingerprint consistency check between browser and fast-path impersonation."""
import re
from dataclasses import dataclass


@dataclass
class FingerprintCheck:
    browser_version: str | None
    impersonate_version: str | None
    matches: bool
    warning: str | None = None


def _major(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(\d+)", value)
    return match.group(1) if match else None


async def check_fingerprint_match(page, impersonate: str) -> FingerprintCheck:
    try:
        ua = await page.evaluate("navigator.userAgent")
    except Exception as exc:
        return FingerprintCheck(
            None, impersonate, False,
            f"could not read navigator.userAgent: {exc}",
        )

    browser_match = re.search(r"Chrome/(\d+)", ua or "")
    browser_version = browser_match.group(1) if browser_match else None
    impersonate_match = re.search(r"chrome(\d+)", impersonate or "")
    impersonate_version = (
        impersonate_match.group(1) if impersonate_match else None
    )

    if browser_version is None:
        return FingerprintCheck(
            None, impersonate_version, False,
            f"could not parse Chrome version from UA: {ua!r}",
        )
    if impersonate_version is None:
        return FingerprintCheck(
            browser_version, None, False,
            f"could not parse version from impersonate={impersonate!r}",
        )

    matches = _major(browser_version) == _major(impersonate_version)
    warning = None
    if not matches:
        warning = (
            f"FINGERPRINT MISMATCH: browser reports Chrome {browser_version}, "
            f"fast path impersonates chrome{impersonate_version}. "
            f"cf_clearance may be rejected by the fast path."
        )
    return FingerprintCheck(
        browser_version,
        impersonate_version,
        matches,
        warning,
    )

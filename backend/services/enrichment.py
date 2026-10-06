import ipaddress
import os
import re
from urllib.parse import urlsplit

import httpx

from models import EnrichmentResult, IOCType

THREATSCAN_API_URL = os.getenv(
    "THREATSCAN_API_URL", "https://threatscan-production.up.railway.app/api"
)


_HASH_RE = re.compile(r"[a-fA-F0-9]{32,64}")
_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_IPV4_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_IPV6_CHARS_RE = re.compile(r"[0-9a-fA-F:.]+")


def detect_ioc_type(ioc: str) -> IOCType:
    """Infer the IOC type when the analyst did not supply one.

    ``AlertIntake.ioc_type`` is optional, and ``case_manager`` already falls
    back to whatever enrichment reports, so enrichment owns the detection.
    Mirrors ``detectType`` in the frontend App.jsx so client and server agree
    on the same indicator.
    """
    value = ioc.strip()
    if not value:
        return IOCType.IP
    if _HASH_RE.fullmatch(value):
        return IOCType.HASH
    if _URL_RE.match(value):
        return IOCType.URL
    if _IPV4_RE.fullmatch(value):
        return IOCType.IP
    if ":" in value and _IPV6_CHARS_RE.fullmatch(value):
        return IOCType.IP
    return IOCType.DOMAIN


# What a stated type must look like. Stricter than detection on purpose:
# detection has to pick something for any input, while these only confirm what
# the caller claimed.
#   hash   MD5, SHA-1 or SHA-256 in hex: exactly 32, 40 or 64 characters.
#   domain at least two dot-separated labels of letters, digits, hyphens and
#          underscores (seen in real malicious subdomains), no label starting or
#          ending with a hyphen, a TLD of letters or an IDN "xn--" label, 253
#          characters at most, one optional trailing dot.
_STATED_HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_DOMAIN_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_DOMAIN_RE = re.compile(
    rf"(?:{_DOMAIN_LABEL}\.)+(?:[A-Za-z]{{2,63}}|xn--[A-Za-z0-9-]{{1,59}})\.?"
)


def ioc_matches_type(ioc: str, ioc_type: IOCType) -> bool:
    """Whether ``ioc`` is a well-formed indicator of the stated ``ioc_type``.

    Checks the value exactly as given, surrounding whitespace included, because
    that is the value enrichment and the report receive.
    """
    if ioc_type is IOCType.IP:
        try:
            ipaddress.ip_address(ioc)
        except ValueError:
            return False
        return True
    if ioc_type is IOCType.HASH:
        return _STATED_HASH_RE.fullmatch(ioc) is not None
    if ioc_type is IOCType.URL:
        if any(ch.isspace() for ch in ioc):
            return False
        try:
            parts = urlsplit(ioc)
            hostname = parts.hostname
        except ValueError:
            return False
        return parts.scheme.lower() in ("http", "https") and bool(hostname)
    # IOCType.DOMAIN
    return len(ioc) <= 253 and _DOMAIN_RE.fullmatch(ioc) is not None


async def enrich_ioc(ioc: str, ioc_type: IOCType | None = None) -> EnrichmentResult:
    """Enrich one IOC through ThreatScan, never raising on a transport failure.

    ``ioc_type`` is optional because the intake model makes it optional; when it
    is omitted the type is detected here. Passing it straight through used to
    put ``None`` into ``EnrichmentResult.ioc_type``, which is a required string,
    so a triage request that left the type out failed with a 500 in both the
    success and the fallback branch.
    """
    resolved_type = ioc_type if ioc_type is not None else detect_ioc_type(ioc)
    url = f"{THREATSCAN_API_URL}/scan"
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(url, json={"query": ioc})
            resp.raise_for_status()
            data = resp.json()
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=resolved_type,
                verdict=data.get("verdict", "unknown"),
                score=data.get("score", 0),
                engines=data.get("engines", []),
            )
        except Exception:
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=resolved_type,
                verdict="error",
                score=0,
                engines=[],
            )

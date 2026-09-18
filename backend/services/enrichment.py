import os
import re

import httpx

from models import EnrichmentResult, IOCType

THREATSCAN_API_URL = os.getenv(
    "THREATSCAN_API_URL", "https://threatscan-production.up.railway.app/api"
)


_HASH_RE = re.compile(r"[a-fA-F0-9]{32,64}")
_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_IPV4_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")


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
    return IOCType.DOMAIN


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

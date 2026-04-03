import httpx
import os
from models import EnrichmentResult, IOCType

THREATSCAN_API_URL = os.getenv(
    "THREATSCAN_API_URL", "https://threatscan-production.up.railway.app/api"
)


async def enrich_ioc(ioc: str, ioc_type: IOCType) -> EnrichmentResult:
    url = f"{THREATSCAN_API_URL}/scan"
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(url, json={"query": ioc})
            resp.raise_for_status()
            data = resp.json()
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                verdict=data.get("verdict", "unknown"),
                score=data.get("score", 0),
                engines=data.get("engines", []),
            )
        except Exception:
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                verdict="error",
                score=0,
                engines=[],
            )

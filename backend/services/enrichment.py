import httpx
import os
from models import EnrichmentResult, EngineResult


THREATSCAN_URL = os.getenv("THREATSCAN_API_URL", "https://threatscan-production.up.railway.app/api")


async def enrich_ioc(ioc: str, ioc_type: str) -> EnrichmentResult:
    """
    Send IOC to ThreatScan API and return structured enrichment result.
    ThreatScan queries 11 engines simultaneously — we just consume the result.
    """
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{THREATSCAN_URL}/scan",
                json={"query": ioc, "type": ioc_type}
            )
            response.raise_for_status()
            data = response.json()

        # Parse engine results
        engines = []
        for engine in data.get("engines", []):
            engines.append(EngineResult(
                id      = engine.get("id", "unknown"),
                verdict = engine.get("verdict", "info"),
                detail  = engine.get("detail"),
                score   = engine.get("score"),
            ))

        return EnrichmentResult(
            ioc      = ioc,
            ioc_type = ioc_type,
            verdict  = data.get("verdict", "unknown"),
            score    = data.get("score", 0),
            engines  = engines,
        )

    except httpx.TimeoutException:
        return EnrichmentResult(
            ioc=ioc, ioc_type=ioc_type,
            verdict="error", score=0,
            engines=[EngineResult(id="threatscan", verdict="error",
                                  detail="ThreatScan timeout")]
        )
    except Exception as err:
        return EnrichmentResult(
            ioc=ioc, ioc_type=ioc_type,
            verdict="error", score=0,
            engines=[EngineResult(id="threatscan", verdict="error",
                                  detail=str(err)[:200])]
 

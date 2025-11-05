import os
from typing import Optional, Dict, Any
from urllib.parse import urlencode
import httpx
from ..config import settings

DEFAULT_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "SAP-ContextId-Accept": "header",
    "X-Requested-With": "XMLHttpRequest",
}

def _build_url(service_name: str, entity_set: str, key_value: str | None = None) -> str:
    """
    Build an SAP OData URL with optional ('key') address and ?sap-client=xxx if provided.
    """
    base = settings.SAP_BASE_URL.rstrip("/")
    path = f"{base}/{service_name}/{entity_set}"
    if key_value:
        path += f"('{key_value}')"
    params = {}
    if settings.SAP_CLIENT:
        params["sap-client"] = settings.SAP_CLIENT
    return f"{path}?{urlencode(params)}" if params else path

async def _fetch_csrf(client: httpx.AsyncClient, probe_url: str, auth):
    # Request a CSRF token; cookies persist in client automatically.
    r = await client.get(probe_url, headers={**DEFAULT_HEADERS, "X-CSRF-Token": "Fetch"}, auth=auth)
    r.raise_for_status()
    token = r.headers.get("x-csrf-token") or r.headers.get("X-CSRF-Token")

    if not token:
        # As a fallback, try the service root (/sap/opu/odata/sap/<service>)
        # by trimming the entity path.
        # probe_url = .../<service>/<entity>(...) ; split to service root
        parts = probe_url.split("/sap/opu/odata/sap/")
        if len(parts) >= 2:
            tail = parts[1]
            service = tail.split("/")[0]
            root = settings.SAP_BASE_URL.rstrip("/") + f"/{service}"
            r2 = await client.get(root, headers={**DEFAULT_HEADERS, "X-CSRF-Token": "Fetch"}, auth=auth)
            r2.raise_for_status()
            token = r2.headers.get("x-csrf-token") or r2.headers.get("X-CSRF-Token")

    if not token:
        raise RuntimeError("Failed to fetch CSRF token from SAP OData endpoint.")
    return token

class SAPClient:
    @staticmethod
    async def call(
        service_name: str,
        entity_set: str,
        key_value: Optional[str],
        payload: Dict[str, Any],
        method: str,
    ):
        """
        Performs GET/POST/PATCH with CSRF handling for state-changing methods.
        """
        url = _build_url(service_name, entity_set, key_value)
        auth = (settings.SAP_USERNAME, settings.SAP_PASSWORD) if settings.SAP_USERNAME else None
        m = (method or "GET").upper()

        async with httpx.AsyncClient(timeout=60.0) as client:
            if m == "GET":
                r = await client.get(url, headers=DEFAULT_HEADERS, auth=auth)
                r.raise_for_status()
                return r.json()

            # Fetch CSRF token for state-changing calls
            token = await _fetch_csrf(client, url, auth)
            headers = {**DEFAULT_HEADERS, "X-CSRF-Token": token}

            if m in ("PATCH", "MERGE"):
                r = await client.patch(url, json=payload, headers=headers, auth=auth)
            elif m == "POST":
                r = await client.post(url, json=payload, headers=headers, auth=auth)
            elif m == "DELETE":
                r = await client.delete(url, headers=headers, auth=auth)
            else:
                r = await client.get(url, headers=DEFAULT_HEADERS, auth=auth)

            r.raise_for_status()
            if r.status_code == 204 or not r.content:
                return {"status": "OK", "http_status": r.status_code}
            return r.json()

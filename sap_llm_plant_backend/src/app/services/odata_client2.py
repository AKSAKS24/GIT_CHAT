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

def _qs() -> str:
    """Build optional query string like ?sap-client=100."""
    params = {}
    if settings.SAP_CLIENT:
        params["sap-client"] = settings.SAP_CLIENT
    return f"?{urlencode(params)}" if params else ""

def _service_base() -> str:
    return settings.SAP_BASE_URL.rstrip("/")

def _entityset_url(service_name: str, entity_set: str) -> str:
    """Generic EntitySet root (no key). Used for CSRF fetch and generic GET."""
    return f"{_service_base()}/{service_name}/{entity_set}{_qs()}"

def _entity_url(service_name: str, entity_set: str, key_value: Optional[str]) -> str:
    """Entity URL (with key) for state-changing calls. If no key, falls back to EntitySet."""
    if key_value:
        return f"{_service_base()}/{service_name}/{entity_set}('{key_value}'){_qs()}"
    return _entityset_url(service_name, entity_set)

async def _fetch_csrf_from_entityset(client: httpx.AsyncClient, service_name: str, entity_set: str, auth) -> str:
    """Fetch CSRF from the EntitySet root (no key)."""
    probe = _entityset_url(service_name, entity_set)
    r = await client.get(probe, headers={**DEFAULT_HEADERS, "X-CSRF-Token": "Fetch"}, auth=auth)
    r.raise_for_status()
    token = r.headers.get("x-csrf-token") or r.headers.get("X-CSRF-Token")
    if token:
        return token

    # Fallback: try service root (…/sap/opu/odata/sap/<service>)
    base = _service_base()
    root = f"{base}/{service_name.split('/')[-1]}{_qs()}"
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
        Performs GET/POST/PATCH/DELETE with CSRF handled via a generic GET
        to the EntitySet root (no key).
        """
        auth = (settings.SAP_USERNAME, settings.SAP_PASSWORD) if settings.SAP_USERNAME else None
        m = (method or "GET").upper()

        async with httpx.AsyncClient(timeout=60.0) as client:
            if m == "GET":
                # Generic GET (no key) as requested
                url = _entityset_url(service_name, entity_set)
                r = await client.get(url, headers=DEFAULT_HEADERS, auth=auth)
                r.raise_for_status()
                return r.json()

            # State-changing: fetch CSRF from generic EntitySet
            token = await _fetch_csrf_from_entityset(client, service_name, entity_set, auth)
            headers = {**DEFAULT_HEADERS, "X-CSRF-Token": token}

            target_url = _entity_url(service_name, entity_set, key_value)

            if m in ("PATCH", "MERGE"):
                r = await client.patch(target_url, json=payload, headers=headers, auth=auth)
            elif m == "POST":
                r = await client.post(target_url, json=payload, headers=headers, auth=auth)
            elif m == "DELETE":
                r = await client.delete(target_url, headers=headers, auth=auth)
            else:
                # Fallback to generic GET if unknown method
                r = await client.get(_entityset_url(service_name, entity_set), headers=DEFAULT_HEADERS, auth=auth)

            r.raise_for_status()
            if r.status_code == 204 or not r.content:
                return {"status": "OK", "http_status": r.status_code}
            return r.json()

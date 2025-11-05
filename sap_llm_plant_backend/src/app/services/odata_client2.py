from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from loguru import logger

# NOTE: adjust this import if your settings path differs
from ..config import settings

# -----------------------------
# Tunables (no redesign needed)
# -----------------------------

# If your gateway needs POST to /EntitySet('key') instead of /EntitySet
POST_REQUIRE_KEY_IN_URL = False

# Where to fetch CSRF from before POST/PATCH/DELETE:
#   "entityset"  -> /Service/EntitySet
#   "service"    -> /Service    (root)
CSRF_FETCH_FROM = "entityset"   # change to "service" if your gateway prefers that

# Wrap responses in a standard envelope
RETURN_WRAPPED = True

# Retry policy
RETRY_ATTEMPTS = 3
RETRY_BASE_DELAY_SEC = 0.75

# Default headers (merged with auth + CSRF)
DEFAULT_HEADERS: Dict[str, str] = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "SAP-ContextId-Accept": "header",
    "X-Requested-With": "XMLHttpRequest",
}

# -------------------------------------------------
# Helpers: URL building (no registry dependency)
# -------------------------------------------------

def _base() -> str:
    if not settings.SAP_BASE_URL:
        raise RuntimeError("SAP_BASE_URL is not configured in .env")
    return settings.SAP_BASE_URL.rstrip("/")

def _svc(service_name: str) -> str:
    # keep only technical service at the end if a path was passed accidentally
    if not service_name:
        raise ValueError("service_name is required")
    return service_name.strip("/").split("/")[-1]

def _qs() -> str:
    params = {}
    if getattr(settings, "SAP_CLIENT", None):
        params["sap-client"] = settings.SAP_CLIENT
    return f"?{urlencode(params)}" if params else ""

def _entityset_url(service_name: str, entity_set: str) -> str:
    if not entity_set:
        raise ValueError("entity_set is required")
    url = f"{_base()}/{_svc(service_name)}/{entity_set}{_qs()}"
    logger.debug(f"[OData] EntitySet URL: {url}")
    return url

def _entity_url(service_name: str, entity_set: str, key_value: Optional[str]) -> str:
    if not entity_set:
        raise ValueError("entity_set is required")
    if key_value:
        url = f"{_base()}/{_svc(service_name)}/{entity_set}('{key_value}'){_qs()}"
    else:
        url = f"{_base()}/{_svc(service_name)}/{entity_set}{_qs()}"
    logger.debug(f"[OData] Entity URL: {url}")
    return url

# -------------------------------------------------
# Helpers: auth & CSRF
# -------------------------------------------------

def _auth_headers() -> Dict[str, str]:
    mode = (getattr(settings, "SAP_AUTH_MODE", "basic") or "basic").lower()
    if mode == "basic":
        user = getattr(settings, "SAP_USERNAME", None)
        pw   = getattr(settings, "SAP_PASSWORD", None)
        if not user:
            raise RuntimeError("SAP_AUTH_MODE=basic but SAP_USERNAME is missing")
        import base64
        token = base64.b64encode(f"{user}:{pw or ''}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    if mode == "oauth2":
        tok = getattr(settings, "SAP_OAUTH_TOKEN", None)
        if not tok:
            raise RuntimeError("SAP_AUTH_MODE=oauth2 but SAP_OAUTH_TOKEN is missing")
        return {"Authorization": f"Bearer {tok}"}
    return {}

async def _fetch_csrf(client: httpx.AsyncClient, service_name: str, entity_set: str) -> Dict[str, Any]:
    """Fetch CSRF token + cookies from the configured probe path."""
    if CSRF_FETCH_FROM == "service":
        probe = f"{_base()}/{_svc(service_name)}{_qs()}"
    else:
        probe = _entityset_url(service_name, entity_set)  # default

    headers = {**_auth_headers(), "X-CSRF-Token": "Fetch", "Accept": "application/json"}
    r = await client.get(probe, headers=headers)
    r.raise_for_status()
    token = r.headers.get("x-csrf-token") or r.headers.get("X-CSRF-Token")
    if not token:
        logger.warning("CSRF token not returned; check SAP config/policy.")
    return {"token": token, "cookies": r.cookies}

# -------------------------------------------------
# Hooks: payload/response shaping (customize here)
# -------------------------------------------------

def shape_outgoing_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Central place to remap your outgoing payload BEFORE sending to SAP.
    Example: map business labels to technical names, strip nulls, etc.
    Default: pass-through.
    """
    # Example (commented):
    # mapping = {"City": "CITY", "Street": "STREET"}
    # return {mapping.get(k, k): v for k, v in payload.items() if v is not None}
    return {k: v for k, v in (payload or {}).items() if v is not None}

def shape_incoming_response(data: Any) -> Any:
    """
    Central place to wrap or normalize SAP response BEFORE returning to caller.
    Default: wrap if RETURN_WRAPPED=True.
    """
    if not RETURN_WRAPPED:
        return data
    return {"ok": True, "data": data}

def shape_error_response(exc: Exception) -> Any:
    if not RETURN_WRAPPED:
        raise
    return {"ok": False, "error": str(exc)}

# -------------------------------------------------
# HTTP retry wrapper
# -------------------------------------------------

async def _request_with_retry(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
    last_exc: Optional[BaseException] = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            r = await client.request(method, url, **kwargs)
            if r.status_code in {429, 502, 503, 504}:
                raise httpx.HTTPStatusError(f"transient {r.status_code}", request=r.request, response=r)
            return r
        except Exception as e:
            last_exc = e
            logger.warning(f"[OData] Attempt {attempt}/{RETRY_ATTEMPTS} failed for {method} {url}: {e}")
            if attempt < RETRY_ATTEMPTS:
                await asyncio.sleep(RETRY_BASE_DELAY_SEC * attempt)
    if last_exc:
        raise last_exc
    raise RuntimeError("request failed (no exception)")

# -------------------------------------------------
# Public client (keeps your existing signature)
# -------------------------------------------------

class SAPClient:
    """
    Backwards-compatible client:
        await SAPClient.call(service, entity, key, payload, method)
    with:
        - generic GET for reads (EntitySet root)
        - CSRF for POST/PATCH/DELETE (probe per CSRF_FETCH_FROM)
        - optional POST with key in URL (POST_REQUIRE_KEY_IN_URL)
        - payload/response shaping hooks (shape_outgoing_payload / shape_incoming_response)
    """

    @staticmethod
    async def call(
        service_name: str,
        entity_set: str,
        key_value: Optional[str],
        payload: Dict[str, Any],
        method: str,
    ) -> Any:
        m = (method or "GET").upper()

        # Build target URLs
        entityset_url = _entityset_url(service_name, entity_set)
        target_url    = _entity_url(service_name, entity_set, key_value)

        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            try:
                if m == "GET":
                    # generic list/read
                    headers = {**_auth_headers(), **DEFAULT_HEADERS}
                    logger.info(f"[OData] GET  {entityset_url}")
                    r = await _request_with_retry(client, "GET", entityset_url, headers=headers)
                    r.raise_for_status()
                    data = r.json() if r.content else {"status": r.status_code}
                    return shape_incoming_response(data)

                # State-changing → CSRF
                csrf = await _fetch_csrf(client, service_name, entity_set)
                headers = {**_auth_headers(), **DEFAULT_HEADERS}
                if csrf.get("token"):
                    headers["X-CSRF-Token"] = csrf["token"]

                # Choose POST URL form
                url_for_write = target_url
                if m == "POST" and POST_REQUIRE_KEY_IN_URL and not key_value:
                    raise ValueError("POST requires key_value (POST_REQUIRE_KEY_IN_URL=True).")

                outgoing = shape_outgoing_payload(payload or {})

                logger.info(f"[OData] {m}  {url_for_write}  (payload keys: {list(outgoing.keys())})")
                if m in ("PATCH", "MERGE"):
                    r = await _request_with_retry(client, "PATCH", url_for_write, headers=headers, json=outgoing, cookies=csrf.get("cookies"))
                elif m == "POST":
                    r = await _request_with_retry(client, "POST", url_for_write, headers=headers, json=outgoing, cookies=csrf.get("cookies"))
                elif m == "DELETE":
                    r = await _request_with_retry(client, "DELETE", url_for_write, headers=headers, cookies=csrf.get("cookies"))
                else:
                    # fallback to a simple GET if unknown method
                    r = await _request_with_retry(client, "GET", entityset_url, headers=headers)

                r.raise_for_status()
                if r.status_code == 204 or not r.content:
                    return shape_incoming_response({"status": "OK", "http_status": r.status_code})
                return shape_incoming_response(r.json())

            except Exception as e:
                logger.error(f"[OData] call failed: {e}")
                return shape_error_response(e)

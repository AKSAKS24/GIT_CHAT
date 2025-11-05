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
POST_REQUIRE_KEY_IN_URL = False  # <-- leave False to avoid key in POST URL

# Optional: when posting WITHOUT key in URL, put the key into payload under this field name.
# Set to your entity's technical key field (e.g., "PLANT"). Leave None to skip auto-injection.
POST_KEY_FIELD_NAME: str | None = "PLANT"

# Where to fetch CSRF from before POST/PATCH/DELETE:
#   "entityset"  -> /Service/EntitySet
#   "service"    -> /Service    (root)
CSRF_FETCH_FROM = "service"  # service-root CSRF probe

# Use this query parameter name for client ("sap-client" is standard)
S_CLIENT_PARAM = "sap-client"

# Include ?sap-client on the CSRF probe (some gateways want it, some don’t)
INCLUDE_CLIENT_ON_CSRF = True

# Wrap responses in a standard envelope
RETURN_WRAPPED = True

# Retry policy
RETRY_ATTEMPTS = 3
RETRY_BASE_DELAY_SEC = 0.75

# Use MERGE semantics for updates (helps some gateways)
USE_MERGE_FOR_PATCH = True

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
        params[S_CLIENT_PARAM] = settings.SAP_CLIENT
    return f"?{urlencode(params)}" if params else ""

def _service_root_url(service_name: str) -> str:
    """
    http://host:port/sap/opu/odata/sap/<SERVICE>/?sap-client=100  (if included)
    """
    url = f"{_base()}/{_svc(service_name)}/"
    if INCLUDE_CLIENT_ON_CSRF:
        return url + _qs()
    return url

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
    """
    Fetch CSRF token + cookies.
    With CSRF_FETCH_FROM='service'   -> /<SERVICE>/?sap-client=...
    With CSRF_FETCH_FROM='entityset' -> /<SERVICE>/<EntitySet>?sap-client=...
    """
    if CSRF_FETCH_FROM == "service":
        probe = _service_root_url(service_name)  # service root (no entity, no key)
    else:
        probe = _entityset_url(service_name, entity_set)

    headers = {**_auth_headers(), "X-CSRF-Token": "Fetch", "Accept": "application/json"}
    logger.info(f"[OData] CSRF GET {probe}")
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
        - GET from EntitySet root
        - CSRF from service root (as configured)
        - POST to EntitySet (no key in URL) UNLESS POST_REQUIRE_KEY_IN_URL=True
        - PATCH/MERGE to Entity('key')
        - payload/response shaping hooks
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
        entity_url    = _entity_url(service_name, entity_set, key_value)

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

                # ----- URL choice & payload shaping -----
                outgoing = shape_outgoing_payload(payload or {})

                if m == "POST":
                    if POST_REQUIRE_KEY_IN_URL:
                        # POST to Entity('key') - rare; only if you explicitly want this
                        if not key_value:
                            raise ValueError("POST requires key_value (POST_REQUIRE_KEY_IN_URL=True).")
                        url_for_write = entity_url
                    else:
                        # ✅ Standard: POST to EntitySet (NO key in URL)
                        url_for_write = entityset_url
                        # Optional: inject key into payload if caller provided key_value
                        if key_value and POST_KEY_FIELD_NAME and POST_KEY_FIELD_NAME not in outgoing:
                            outgoing[POST_KEY_FIELD_NAME] = key_value

                    logger.info(f"[OData] POST {url_for_write} (payload keys: {list(outgoing.keys())})")
                    r = await _request_with_retry(
                        client, "POST", url_for_write, headers=headers,
                        json=outgoing, cookies=csrf.get("cookies")
                    )

                elif m in ("PATCH", "MERGE"):
                    # Updates should target the entity URL with key
                    if not key_value:
                        raise ValueError("PATCH/MERGE requires key_value")
                    url_for_write = entity_url

                    if m == "PATCH" and USE_MERGE_FOR_PATCH:
                        # Use MERGE tunneling via POST (common Gateway pattern)
                        hdrs = {**headers, "X-HTTP-Method": "MERGE"}
                        logger.info(f"[OData] MERGE (via POST) {url_for_write} (payload keys: {list(outgoing.keys())})")
                        r = await _request_with_retry(
                            client, "POST", url_for_write, headers=hdrs,
                            json=outgoing, cookies=csrf.get("cookies")
                        )
                    else:
                        meth = "PATCH" if m == "PATCH" else "MERGE"
                        logger.info(f"[OData] {meth} {url_for_write} (payload keys: {list(outgoing.keys())})")
                        r = await _request_with_retry(
                            client, meth, url_for_write, headers=headers,
                            json=outgoing, cookies=csrf.get("cookies")
                        )

                elif m == "DELETE":
                    if not key_value:
                        raise ValueError("DELETE requires key_value")
                    url_for_write = entity_url
                    logger.info(f"[OData] DELETE {url_for_write}")
                    r = await _request_with_retry(
                        client, "DELETE", url_for_write, headers=headers, cookies=csrf.get("cookies")
                    )

                else:
                    # Fallback unknown → simple GET
                    logger.info(f"[OData] GET  {entityset_url}")
                    r = await _request_with_retry(client, "GET", entityset_url, headers=headers)

                r.raise_for_status()
                if r.status_code == 204 or not r.content:
                    return shape_incoming_response({"status": "OK", "http_status": r.status_code})
                return shape_incoming_response(r.json())

            except httpx.HTTPStatusError as e:
                resp = e.response
                err_payload = {
                    "ok": False,
                    "status": resp.status_code if resp else None,
                    "url": str(resp.request.url) if resp and resp.request else None,
                    "body": resp.text[:2000] if resp and resp.text else None,
                    "headers": dict(resp.headers) if resp else None,
                }
                logger.error(f"[OData] HTTP error: {err_payload}")
                return err_payload
            except Exception as e:
                logger.error(f"[OData] call failed: {e}")
                return shape_error_response(e)

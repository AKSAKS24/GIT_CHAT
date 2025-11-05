from __future__ import annotations

import asyncio
import base64
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx
from loguru import logger

from ..config import settings

# -----------------------------
# Tunables (kept minimal)
# -----------------------------

# POST URL style:
POST_REQUIRE_KEY_IN_URL = False  # keep False => POST /EntitySet  (key goes in payload)

# If you pass a key_value and POST has no key in URL, inject it into payload under this field:
POST_KEY_FIELD_NAME: str | None = "PLANT"

# Where to fetch CSRF before POST/PUT/PATCH/DELETE:
#   "service"    -> /Service/
#   "entityset"  -> /Service/EntitySet
CSRF_FETCH_FROM = "service"

# Whether to include ?sap-client=... on CSRF probe:
INCLUDE_CLIENT_ON_CSRF = True

# OData v2 JSON (NetWeaver Gateway) typically wraps payload in {"d": {...}}
WRAP_V2_PAYLOAD = True

# On POST failure (400/403/409), attempt PUT to /EntitySet(Key='value')
POST_FALLBACK_TO_PUT = True

# Retry policy for transient statuses (not CSRF-related)
RETRY_ATTEMPTS = 3
RETRY_BASE_DELAY_SEC = 0.75

# Default headers (merged with auth + CSRF + Cookie)
DEFAULT_HEADERS: Dict[str, str] = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "SAP-ContextId-Accept": "header",
    "X-Requested-With": "XMLHttpRequest",
}

# -----------------------------
# URL helpers
# -----------------------------

def _base() -> str:
    if not settings.SAP_BASE_URL:
        raise RuntimeError("SAP_BASE_URL is not configured in .env")
    return settings.SAP_BASE_URL.rstrip("/")

def _svc(service_name: str) -> str:
    if not service_name:
        raise ValueError("service_name is required")
    return service_name.strip("/").split("/")[-1]

def _qs() -> str:
    params = {}
    if getattr(settings, "SAP_CLIENT", None):
        params["sap-client"] = settings.SAP_CLIENT
    return f"?{urlencode(params)}" if params else ""

def _service_root_url(service_name: str) -> str:
    url = f"{_base()}/{_svc(service_name)}/"
    if INCLUDE_CLIENT_ON_CSRF:
        return url + _qs()
    return url

def _entityset_url(service_name: str, entity_set: str) -> str:
    if not entity_set:
        raise ValueError("entity_set is required")
    return f"{_base()}/{_svc(service_name)}/{entity_set}{_qs()}"

def _entity_url_with_key(service_name: str, entity_set: str, key_field: str, key_value: str) -> str:
    if not entity_set:
        raise ValueError("entity_set is required")
    if not key_field or key_value is None:
        raise ValueError("key_field and key_value are required for key URL")
    # Named key predicate to match your working example: (PLANT='1000')
    return f"{_base()}/{_svc(service_name)}/{entity_set}({key_field}='{key_value}'){_qs()}"

# -----------------------------
# Auth & CSRF helpers
# -----------------------------

def _auth_headers() -> Dict[str, str]:
    mode = (getattr(settings, "SAP_AUTH_MODE", "basic") or "basic").lower()
    if mode == "basic":
        user = getattr(settings, "SAP_USERNAME", None)
        pw   = getattr(settings, "SAP_PASSWORD", None)
        if not user:
            raise RuntimeError("SAP_AUTH_MODE=basic but SAP_USERNAME is missing")
        token = base64.b64encode(f"{user}:{pw or ''}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    if mode == "oauth2":
        tok = getattr(settings, "SAP_OAUTH_TOKEN", None)
        if not tok:
            raise RuntimeError("SAP_AUTH_MODE=oauth2 but SAP_OAUTH_TOKEN is missing")
        return {"Authorization": f"Bearer {tok}"}
    return {}

async def _fetch_csrf_and_cookie_header(
    client: httpx.AsyncClient,
    service_name: str,
    entity_set: Optional[str],
) -> Tuple[str, str]:
    """
    Fetch CSRF token from service root (or entityset if configured) and
    build a Cookie header string exactly like your working requests.Session code.
    """
    if CSRF_FETCH_FROM == "service" or not entity_set:
        probe = _service_root_url(service_name)
    else:
        probe = _entityset_url(service_name, entity_set)

    headers = {
        **_auth_headers(),
        "X-CSRF-Token": "Fetch",
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    logger.info(f"[OData] CSRF GET {probe}")
    r = await client.get(probe, headers=headers)
    r.raise_for_status()

    token = r.headers.get("x-csrf-token") or r.headers.get("X-CSRF-Token") or ""
    # Build Cookie header string from the response cookies (just like requests.get_dict)
    cdict = {c.name: c.value for c in r.cookies.jar} if r.cookies else {}
    cookie_header = "; ".join([f"{k}={v}" for k, v in cdict.items()]) if cdict else ""

    if not token:
        logger.warning("CSRF token not returned; proceeding without token (GW may respond 'Required').")
    if not cookie_header:
        logger.warning("No cookies returned on CSRF fetch; check ICM/GW configuration.")

    return token, cookie_header

# -----------------------------
# Payload shaping
# -----------------------------

def _shape_outgoing(payload: Dict[str, Any]) -> Dict[str, Any]:
    clean = {k: v for k, v in (payload or {}).items() if v not in (None, "", [])}
    return {"d": clean} if WRAP_V2_PAYLOAD else clean

def _unwrap_incoming(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    if "d" in data:
        return data["d"]
    return data

# -----------------------------
# Retry wrapper
# -----------------------------

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

# -----------------------------
# Write helpers (POST/PUT)
# -----------------------------

async def _post_with_csrf(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    token: str,
    cookie_header: str,
) -> httpx.Response:
    headers = {**_auth_headers(), **DEFAULT_HEADERS}
    if token:
        headers["X-CSRF-Token"] = token
    if cookie_header:
        headers["Cookie"] = cookie_header

    logger.info(f"[OData] POST {url} (payload keys: {list((payload.get('d') if WRAP_V2_PAYLOAD else payload).keys())})")
    return await _request_with_retry(client, "POST", url, headers=headers, json=payload)

async def _put_with_csrf(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    token: str,
    cookie_header: str,
) -> httpx.Response:
    headers = {**_auth_headers(), **DEFAULT_HEADERS}
    if token:
        headers["X-CSRF-Token"] = token
    if cookie_header:
        headers["Cookie"] = cookie_header

    logger.info(f"[OData] PUT  {url} (payload keys: {list((payload.get('d') if WRAP_V2_PAYLOAD else payload).keys())})")
    return await _request_with_retry(client, "PUT", url, headers=headers, json=payload)

# -----------------------------
# Public client
# -----------------------------

class SAPClient:
    """
    Backwards-compatible client:
        await SAPClient.call(service, entity, key, payload, method)

    Behavior aligned with your working sample:
      - CSRF GET from service root (with ?sap-client when configured)
      - Manual 'Cookie' header built from CSRF response cookies
      - X-Requested-With on CSRF fetch and writes
      - OData v2 JSON payload wrapped as {"d": {...}}
      - POST to /EntitySet (no key in URL) with key inside payload
      - On POST failure 400/403/409, fallback to PUT /EntitySet(Key='value')
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

        entityset_url = _entityset_url(service_name, entity_set)
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            try:
                if m == "GET":
                    headers = {**_auth_headers(), **DEFAULT_HEADERS}
                    logger.info(f"[OData] GET  {entityset_url}")
                    r = await _request_with_retry(client, "GET", entityset_url, headers=headers)
                    r.raise_for_status()
                    if r.content:
                        return _unwrap_incoming(r.json())
                    return {"status": r.status_code}

                # --- CSRF + Cookie (from CSRF response) ---
                token, cookie_header = await _fetch_csrf_and_cookie_header(client, service_name, entity_set)
                outgoing = _shape_outgoing(
                    {**(payload or {}), **({POST_KEY_FIELD_NAME: key_value} if (POST_KEY_FIELD_NAME and key_value and not (payload or {}).get(POST_KEY_FIELD_NAME)) else {})}
                )

                if m == "POST":
                    post_url = entityset_url
                    r = await _post_with_csrf(client, post_url, outgoing, token, cookie_header)

                    if r.status_code in (200, 201):
                        return _unwrap_incoming(r.json()) if r.text else {"status": "created"}

                    # Fallback to PUT if enabled (existing record)
                    if POST_FALLBACK_TO_PUT and r.status_code in (400, 403, 409):
                        if not POST_KEY_FIELD_NAME or not (key_value or (payload or {}).get(POST_KEY_FIELD_NAME)):
                            raise ValueError("PUT fallback requires a key (POST_KEY_FIELD_NAME and value).")
                        eff_key_val = key_value or (payload or {}).get(POST_KEY_FIELD_NAME)
                        put_url = _entity_url_with_key(service_name, entity_set, POST_KEY_FIELD_NAME, str(eff_key_val))
                        logger.warning(f"[OData] POST failed ({r.status_code}), attempting PUT {put_url} ...")
                        r2 = await _put_with_csrf(client, put_url, outgoing, token, cookie_header)
                        if r2.status_code in (200, 204):
                            return {"status": "success", "message": f"{entity_set} updated for {POST_KEY_FIELD_NAME}={eff_key_val}"}
                        r2.raise_for_status()

                    r.raise_for_status()
                    return _unwrap_incoming(r.json()) if r.text else {"status": r.status_code}

                if m == "PUT":
                    if not POST_KEY_FIELD_NAME:
                        raise ValueError("PUT requires POST_KEY_FIELD_NAME to build key URL.")
                    eff_key_val = key_value or (payload or {}).get(POST_KEY_FIELD_NAME)
                    if eff_key_val in (None, ""):
                        raise ValueError("PUT requires a key value (either key_value param or in payload).")
                    put_url = _entity_url_with_key(service_name, entity_set, POST_KEY_FIELD_NAME, str(eff_key_val))
                    r = await _put_with_csrf(client, put_url, outgoing, token, cookie_header)
                    if r.status_code in (200, 204):
                        return {"status": "success", "message": f"{entity_set} updated for {POST_KEY_FIELD_NAME}={eff_key_val}"}
                    r.raise_for_status()
                    return _unwrap_incoming(r.json()) if r.text else {"status": r.status_code}

                # Optional: PATCH/MERGE support if you need them later
                if m in ("PATCH", "MERGE", "DELETE"):
                    raise NotImplementedError(f"{m} not implemented in this hardened path (stick to POST/PUT).")

                # Fallback unknown → GET
                headers = {**_auth_headers(), **DEFAULT_HEADERS}
                logger.info(f"[OData] GET  {entityset_url}")
                r = await _request_with_retry(client, "GET", entityset_url, headers=headers)
                r.raise_for_status()
                return _unwrap_incoming(r.json()) if r.content else {"status": r.status_code}

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
                return {"ok": False, "error": str(e)}

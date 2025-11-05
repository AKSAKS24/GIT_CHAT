from __future__ import annotations

import asyncio
import base64
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx
from loguru import logger

# Adjust if your settings path differs
from ..config import settings

# =========================
# Tunables (minimal, safe)
# =========================

# POST URL has NO key; key must be in payload
POST_REQUIRE_KEY_IN_URL = False

# Name of technical key field to inject into payload when key_value provided
POST_KEY_FIELD_NAME: str | None = "PLANT"

# CSRF fetch origin: "service" -> /Service/, "entityset" -> /Service/EntitySet
CSRF_FETCH_FROM = "service"

# Include ?sap-client on CSRF fetch URL
INCLUDE_CLIENT_ON_CSRF = True

# OData v2 envelope {"d": {...}}
WRAP_V2_PAYLOAD = True

# Fallback to PUT when POST returns 400/403/409 (record exists or policy)
POST_FALLBACK_TO_PUT = True

# One retry on 403 x-csrf-token: Required
RETRY_ON_403_CSRF = True

# Retry policy for transient statuses
RETRY_ATTEMPTS = 3
RETRY_BASE_DELAY_SEC = 0.75

# Default headers merged into requests (in addition to auth/CSRF/Cookie)
DEFAULT_HEADERS: Dict[str, str] = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "SAP-ContextId-Accept": "header",
    "X-Requested-With": "XMLHttpRequest",
}

# =========================
# URL helpers
# =========================

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
    # Named key predicate for OData v2: (PLANT='1000')
    return f"{_base()}/{_svc(service_name)}/{entity_set}({key_field}='{key_value}'){_qs()}"

# =========================
# Auth & CSRF helpers
# =========================

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
    GET CSRF at service root (or entityset), return (token, "Cookie" header string).
    Mirrors your known-good requests.Session behavior.
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
    # Build Cookie header manually from response cookies (same as requests' get_dict)
    cdict = {c.name: c.value for c in r.cookies.jar} if r.cookies else {}
    cookie_header = "; ".join(f"{k}={v}" for k, v in cdict.items()) if cdict else ""

    if not token:
        logger.warning("CSRF token not returned; proceeding without token (GW may respond 'Required').")
    if not cookie_header:
        logger.warning("No cookies returned on CSRF fetch; check ICM/Gateway cookie policy.")

    return token, cookie_header

# =========================
# Payload shaping (OData v2)
# =========================

def _shape_outgoing(payload: Dict[str, Any]) -> Dict[str, Any]:
    clean = {k: v for k, v in (payload or {}).items() if v not in (None, "", [])}
    return {"d": clean} if WRAP_V2_PAYLOAD else clean

def _unwrap_incoming(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    if "d" in data:
        return data["d"]
    return data

# =========================
# Retry wrapper
# =========================

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

# =========================
# Write helpers (POST/PUT)
# =========================

def _compose_cookie_header(token: str, cookie_header: str) -> Dict[str, str]:
    hdrs = {**_auth_headers(), **DEFAULT_HEADERS}
    if token:
        hdrs["X-CSRF-Token"] = token
    if cookie_header:
        hdrs["Cookie"] = cookie_header
    return hdrs

async def _post_with_csrf(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    token: str,
    cookie_header: str,
) -> httpx.Response:
    headers = _compose_cookie_header(token, cookie_header)
    logger.info(f"[OData] POST {url} (payload keys: {list((payload.get('d') if WRAP_V2_PAYLOAD else payload).keys())})")
    return await _request_with_retry(client, "POST", url, headers=headers, json=payload)

async def _put_with_csrf(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    token: str,
    cookie_header: str,
) -> httpx.Response:
    headers = _compose_cookie_header(token, cookie_header)
    logger.info(f"[OData] PUT  {url} (payload keys: {list((payload.get('d') if WRAP_V2_PAYLOAD else payload).keys())})")
    return await _request_with_retry(client, "PUT", url, headers=headers, json=payload)

async def _write_with_auto_retry_on_required(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]],
    token: str,
    cookie_header: str,
    service_name: str,
    entity_set: str,
) -> httpx.Response:
    """
    Executes write once; if 403 + x-csrf-token: Required, refetch CSRF & Cookie and retry once.
    """
    headers = _compose_cookie_header(token, cookie_header)
    r = await _request_with_retry(client, method, url, headers=headers, json=payload)

    if RETRY_ON_403_CSRF and r.status_code == 403:
        need = r.headers.get("x-csrf-token") or r.headers.get("X-CSRF-Token")
        if need and need.lower() == "required":
            logger.warning("[OData] 403 with x-csrf-token: Required — refetching CSRF/Cookie and retrying once")
            new_token, new_cookie = await _fetch_csrf_and_cookie_header(client, service_name, entity_set)
            headers = _compose_cookie_header(new_token, new_cookie)
            r = await _request_with_retry(client, method, url, headers=headers, json=payload)
    return r

# =========================
# Public client
# =========================

class SAPClient:
    """
    await SAPClient.call(service, entity, key, payload, method)

    - CSRF GET from service root (or entityset) with X-Requested-With
    - Manual "Cookie" header mirrors your working requests example
    - OData v2 body {"d": {...}}
    - POST -> /EntitySet  (key in payload, NOT in URL)
    - On POST 400/403/409 -> PUT /EntitySet(Key='value')
    - GET returns unwrapped JSON (d/results handling left to caller)
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
                    return _unwrap_incoming(r.json()) if r.content else {"status": r.status_code}

                # CSRF token + Cookie
                token, cookie_header = await _fetch_csrf_and_cookie_header(client, service_name, entity_set)

                # Build outgoing payload: inject key_field into body if provided as param
                base_payload = payload or {}
                if POST_KEY_FIELD_NAME and key_value and POST_KEY_FIELD_NAME not in base_payload:
                    base_payload = {**base_payload, POST_KEY_FIELD_NAME: key_value}
                outgoing = _shape_outgoing(base_payload)

                if m == "POST":
                    # Always POST to EntitySet (no key in URL)
                    post_url = entityset_url
                    r = await _write_with_auto_retry_on_required(
                        client, "POST", post_url, outgoing, token, cookie_header, service_name, entity_set
                    )

                    if r.status_code in (200, 201):
                        return _unwrap_incoming(r.json()) if r.text else {"status": "created"}

                    # Existing record / policy: fallback to PUT with named key predicate
                    if POST_FALLBACK_TO_PUT and r.status_code in (400, 403, 409):
                        if not POST_KEY_FIELD_NAME:
                            raise ValueError("PUT fallback requires POST_KEY_FIELD_NAME (entity key field).")
                        eff_key_val = key_value or base_payload.get(POST_KEY_FIELD_NAME)
                        if eff_key_val in (None, ""):
                            raise ValueError("PUT fallback requires a key value (either key_value or in payload).")
                        put_url = _entity_url_with_key(service_name, entity_set, POST_KEY_FIELD_NAME, str(eff_key_val))
                        logger.warning(f"[OData] POST failed ({r.status_code}); attempting PUT {put_url} ...")
                        r2 = await _write_with_auto_retry_on_required(
                            client, "PUT", put_url, outgoing, token, cookie_header, service_name, entity_set
                        )
                        if r2.status_code in (200, 204):
                            return {"status": "success", "message": f"{entity_set} updated for {POST_KEY_FIELD_NAME}={eff_key_val}"}
                        r2.raise_for_status()

                    # If we get here, raise
                    r.raise_for_status()
                    return _unwrap_incoming(r.json()) if r.text else {"status": r.status_code}

                if m == "PUT":
                    if not POST_KEY_FIELD_NAME:
                        raise ValueError("PUT requires POST_KEY_FIELD_NAME to construct key URL.")
                    eff_key_val = key_value or payload.get(POST_KEY_FIELD_NAME) if payload else None
                    if eff_key_val in (None, ""):
                        raise ValueError("PUT requires a key value (either key_value or in payload).")
                    put_url = _entity_url_with_key(service_name, entity_set, POST_KEY_FIELD_NAME, str(eff_key_val))
                    r = await _write_with_auto_retry_on_required(
                        client, "PUT", put_url, outgoing, token, cookie_header, service_name, entity_set
                    )
                    if r.status_code in (200, 204):
                        return {"status": "success", "message": f"{entity_set} updated for {POST_KEY_FIELD_NAME}={eff_key_val}"}
                    r.raise_for_status()
                    return _unwrap_incoming(r.json()) if r.text else {"status": r.status_code}

                # (Optional) Implement PATCH/MERGE/DELETE similarly if needed
                if m in ("PATCH", "MERGE", "DELETE"):
                    raise NotImplementedError(f"{m} not implemented in this hardened path (use POST/PUT).")

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

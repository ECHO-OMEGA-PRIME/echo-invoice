"""Security layer for echo-invoice — vault-backed secrets, authz, input validation.

Secrets load order: vault (echo-invoice service via vault.read_secret / echo.vault.get)
  -> environment -> sovereign key file. No hardcoded credential defaults in production paths.

Authz tiers (ENDPOINT_AUTH):
  public  — health, status, public payment return pages
  read    — list/query tenant-scoped data, reports, plans, dashboard
  write   — create/update invoices, payments, estimates, billing checkout
  admin   — stripe migrate, global activity without tenant scope
  webhook — Stripe signature verification (not API key)
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime
from typing import Any

from fastapi import Header, HTTPException, Request

logger = logging.getLogger("echo_invoice.security")

VAULT_SERVICE = "echo-invoice"
SDK_GATE_URL = os.environ.get("SDK_GATE_URL", os.environ.get("ECHO_SDK_GATE_URL", "http://127.0.0.1:8000"))
VAULT_URL = os.environ.get("VAULT_API_URL", os.environ.get("ECHO_VAULT_URL", ""))
DEV_MODE_ENV = "ECHO_INVOICE_DEV_MODE"

AUTH_PUBLIC = "public"
AUTH_READ = "read"
AUTH_WRITE = "write"
AUTH_ADMIN = "admin"
AUTH_WEBHOOK = "webhook"

# Logical endpoint keys → auth tier. Used by auth_dependency and path resolver.
ENDPOINT_AUTH: dict[str, str] = {
    "health": AUTH_PUBLIC,
    "ready": AUTH_PUBLIC,
    "resilience": AUTH_PUBLIC,
    "resilience.flush": AUTH_ADMIN,
    "status": AUTH_PUBLIC,
    "api": AUTH_PUBLIC,
    "public.payment_success": AUTH_PUBLIC,
    "public.payment_cancelled": AUTH_PUBLIC,
    "billing.plans": AUTH_READ,
    "billing.checkout": AUTH_WRITE,
    "billing.portal": AUTH_WRITE,
    "billing.stats": AUTH_READ,
    "dashboard": AUTH_READ,
    "tenants.list": AUTH_READ,
    "tenants.create": AUTH_WRITE,
    "clients.list": AUTH_READ,
    "clients.create": AUTH_WRITE,
    "invoices.list": AUTH_READ,
    "invoices.get": AUTH_READ,
    "invoices.create": AUTH_WRITE,
    "invoices.update": AUTH_WRITE,
    "invoices.pdf": AUTH_WRITE,
    "payments.list": AUTH_READ,
    "payments.create": AUTH_WRITE,
    "expenses.list": AUTH_READ,
    "expenses.create": AUTH_WRITE,
    "expenses.categories": AUTH_READ,
    "reports.overview": AUTH_READ,
    "reports.aging": AUTH_READ,
    "reports.profit_loss": AUTH_READ,
    "reports.monthly_revenue": AUTH_READ,
    "reports.revenue_by_client": AUTH_READ,
    "reports.clients": AUTH_READ,
    "reports.revenue": AUTH_READ,
    "ai.invoice_optimization": AUTH_WRITE,
    "ai.late_payment_risk": AUTH_WRITE,
    "admin.migrate_stripe": AUTH_ADMIN,
    "webhooks.stripe": AUTH_WEBHOOK,
    "recurring.list": AUTH_READ,
    "recurring.create": AUTH_WRITE,
    "estimates.list": AUTH_READ,
    "estimates.get": AUTH_READ,
    "estimates.create": AUTH_WRITE,
    "estimates.line_items": AUTH_WRITE,
    "estimates.send": AUTH_WRITE,
    "estimates.approve": AUTH_WRITE,
    "estimates.convert": AUTH_WRITE,
    "products.list": AUTH_READ,
    "tax_rates.list": AUTH_READ,
    "credits.list": AUTH_READ,
    "activity.list": AUTH_READ,
}

# Identifiers: alphanumerics, underscore, hyphen, colon, dot — no spaces/SQL metachar
ID_RE = re.compile(r"^[a-zA-Z0-9_.:\-]{1,128}$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
SAFE_NAME_RE = re.compile(r"^[\w\s\-\.'&,/()+#]{1,200}$", re.UNICODE)
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
PHONE_RE = re.compile(r"^[0-9+\-\s().]{0,40}$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9_\-]{1,16}$")
METHOD_WHITELIST = frozenset({"stripe", "cash", "check", "ach", "wire", "paypal", "other", "card", "manual"})
PLAN_WHITELIST = frozenset({"free", "pro", "enterprise"})
INVOICE_STATUS_WHITELIST = frozenset(
    {"draft", "sent", "viewed", "partial", "paid", "overdue", "void", "cancelled", "uncollectible"}
)
ESTIMATE_STATUS_WHITELIST = frozenset({"draft", "sent", "approved", "rejected", "converted", "expired"})
FREQUENCY_WHITELIST = frozenset({"daily", "weekly", "biweekly", "monthly", "quarterly", "yearly", "annual"})
CATEGORY_RE = re.compile(r"^[a-zA-Z0-9 _\-/&]{1,64}$")

_secret_cache: dict[str, tuple[str, float]] = {}
_CACHE_TTL = 300.0


def _cache_get(key: str) -> str | None:
    entry = _secret_cache.get(key)
    if not entry:
        return None
    value, expires = entry
    if time.time() > expires:
        _secret_cache.pop(key, None)
        return None
    return value


def _cache_put(key: str, value: str) -> None:
    _secret_cache[key] = (value, time.time() + _CACHE_TTL)


def clear_secret_cache() -> None:
    """Test helper — drop all cached secrets."""
    _secret_cache.clear()


def _dev_mode() -> bool:
    return os.environ.get(DEV_MODE_ENV, "") in ("1", "true", "yes")


def _load_sovereign_key() -> str:
    cached = _cache_get("ECHO_API_KEY")
    if cached is not None:
        return cached
    for env_name in ("ECHO_INVOICE_API_KEY", "ECHO_API_KEY", "SOVEREIGN_KEY"):
        val = os.environ.get(env_name, "")
        if val:
            _cache_put("ECHO_API_KEY", val)
            return val
    for path in (
        "/home/forge/.echo_sovereign_key",
        os.path.expanduser("~/.echo_sovereign_key"),
    ):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
                if raw.startswith("SOVEREIGN_KEY="):
                    val = raw.split("=", 1)[1].strip()
                else:
                    val = raw
                if val:
                    _cache_put("ECHO_API_KEY", val)
                    return val
        except OSError:
            continue
    return ""


def _http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = 8,
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw[:200]}
        return exc.code, parsed
    except Exception as exc:
        logger.warning("http %s %s failed: %s", method, url, exc)
        return 0, {}


def _sdk_invoke(capability: str, params: dict[str, Any], timeout: int = 8) -> Any:
    api_key = _load_sovereign_key()
    if not api_key:
        return None
    status, data = _http_json(
        f"{SDK_GATE_URL.rstrip('/')}/sdk/invoke",
        method="POST",
        headers={"X-Echo-API-Key": api_key, "Content-Type": "application/json"},
        body={"envelope_version": 1, "capability": capability, "params": params},
        timeout=timeout,
    )
    if status and status < 300 and isinstance(data, dict) and data.get("status") == "ok":
        result = data.get("result") or {}
        if isinstance(result, dict) and "body" in result:
            return result.get("body")
        return result
    return None


def vault_read_secret(service: str, key_name: str | None = None) -> str:
    """Read a secret from Echo Vault.

    Tries capabilities in order (prompt contract + fleet convention):
      1. vault.read_secret
      2. echo.vault.get
    Then optional direct VAULT_URL HTTP. Never raises; returns "" on miss.
    """
    cache_key = f"vault:{service}:{key_name or '*'}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    for capability, params in (
        (
            "vault.read_secret",
            {"command": "read_secret", "service": service, "key_name": key_name},
        ),
        (
            "echo.vault.get",
            {"command": "get", "service": service, "key_name": key_name},
        ),
    ):
        body = _sdk_invoke(capability, params, timeout=8)
        if isinstance(body, dict):
            for field in (key_name, "secret", "password", "api_key", "value"):
                if field and body.get(field):
                    val = str(body[field])
                    _cache_put(cache_key, val)
                    return val
            creds = body.get("credentials")
            if isinstance(creds, dict) and key_name and creds.get(key_name):
                val = str(creds[key_name])
                _cache_put(cache_key, val)
                return val

    if VAULT_URL:
        url = f"{VAULT_URL.rstrip('/')}/credentials/{urllib.parse.quote(service)}"
        if key_name:
            url += f"/{urllib.parse.quote(key_name)}"
        status, data = _http_json(
            url,
            headers={"X-Echo-API-Key": _load_sovereign_key()},
            timeout=6,
        )
        if status and status < 300 and isinstance(data, dict):
            for field in ("secret", "password", "api_key", "value", key_name or ""):
                if field and data.get(field):
                    val = str(data[field])
                    _cache_put(cache_key, val)
                    return val

    return ""


def load_secret(name: str, *, env_names: tuple[str, ...] = (), vault_key: str | None = None) -> str:
    """Resolve a secret: vault.read_secret -> env chain. Never returns hardcoded defaults."""
    cache_key = f"secret:{name}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    vk = vault_key or name
    val = vault_read_secret(VAULT_SERVICE, vk)
    if val:
        _cache_put(cache_key, val)
        return val

    for env_name in env_names or (name,):
        val = os.environ.get(env_name, "")
        if val:
            _cache_put(cache_key, val)
            return val

    return ""


def pg_config() -> dict[str, Any]:
    """Build psycopg2 connect kwargs; password required from vault/env (no default)."""
    password = load_secret(
        "PGPASSWORD",
        env_names=("ECHO_INVOICE_PG_PASSWORD", "PGPASSWORD"),
        vault_key="PGPASSWORD",
    )
    if not password:
        if _dev_mode():
            password = os.environ.get("PGPASSWORD", "")
        if not password:
            raise ValueError(
                "PGPASSWORD not configured — set ECHO_INVOICE_PG_PASSWORD env "
                "or vault echo-invoice:PGPASSWORD via vault.read_secret"
            )
    return {
        "host": os.environ.get("PGHOST", "localhost"),
        "port": int(os.environ.get("PGPORT", "5432")),
        "user": os.environ.get("PGUSER", "echo"),
        "password": password,
        "dbname": os.environ.get("PGDATABASE", "echo"),
        "connect_timeout": 8,
    }


def stripe_secret_key() -> str:
    return load_secret(
        "STRIPE_SECRET_KEY",
        env_names=("ECHO_INVOICE_STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY"),
        vault_key="STRIPE_SECRET_KEY",
    )


def stripe_webhook_secret() -> str:
    return load_secret(
        "STRIPE_WEBHOOK_SECRET",
        env_names=("ECHO_INVOICE_STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET"),
        vault_key="STRIPE_WEBHOOK_SECRET",
    )


def invoice_hmac_key() -> str:
    return load_secret(
        "INVOICE_HMAC_KEY",
        env_names=("ECHO_INVOICE_HMAC_KEY", "INVOICE_HMAC_KEY"),
        vault_key="INVOICE_HMAC_KEY",
    )


def minio_access_key() -> str:
    return load_secret(
        "MINIO_ACCESS_KEY",
        env_names=("ECHO_INVOICE_MINIO_ACCESS_KEY", "MINIO_ACCESS_KEY"),
        vault_key="MINIO_ACCESS_KEY",
    )


def minio_secret_key() -> str:
    return load_secret(
        "MINIO_SECRET_KEY",
        env_names=("ECHO_INVOICE_MINIO_SECRET_KEY", "MINIO_SECRET_KEY"),
        vault_key="MINIO_SECRET_KEY",
    )


def api_key() -> str:
    return _load_sovereign_key()


def _check_auth(endpoint: str, x_echo_api_key: str | None) -> dict[str, Any]:
    """Core authz check for an endpoint tier."""
    tier = ENDPOINT_AUTH.get(endpoint, AUTH_WRITE)
    ctx: dict[str, Any] = {
        "authenticated": False,
        "tier": tier,
        "principal": "anonymous",
        "endpoint": endpoint,
    }

    if tier == AUTH_PUBLIC:
        ctx["authenticated"] = True
        return ctx

    if tier == AUTH_WEBHOOK:
        # Webhook handlers verify signatures themselves.
        raise HTTPException(500, "webhook endpoints use signature auth, not API key")

    expected = api_key()
    if not expected:
        logger.error("auth misconfigured: ECHO_API_KEY not set for endpoint=%s", endpoint)
        raise HTTPException(503, "service auth not configured")

    if not x_echo_api_key:
        raise HTTPException(401, "unauthorized")

    if len(x_echo_api_key) > 2048:
        raise HTTPException(401, "invalid api key")

    if not hmac.compare_digest(x_echo_api_key, expected):
        logger.warning("auth_failure endpoint=%s reason=key_mismatch", endpoint)
        raise HTTPException(401, "unauthorized")

    ctx["authenticated"] = True
    ctx["principal"] = "api_key"
    return ctx


def auth_dependency(endpoint: str):
    """FastAPI dependency factory: enforce tiered authz per endpoint."""

    def _dependency(
        x_echo_api_key: str | None = Header(default=None, alias="X-Echo-API-Key"),
    ) -> dict[str, Any]:
        return _check_auth(endpoint, x_echo_api_key)

    return _dependency


def require_auth(endpoint: str, x_echo_api_key: str | None) -> dict[str, Any]:
    """Programmatic authz gate (non-Depends callers)."""
    return _check_auth(endpoint, x_echo_api_key)


def resolve_endpoint(method: str, path: str) -> str:
    """Map HTTP method+path to ENDPOINT_AUTH key for coverage checks / middleware."""
    method = (method or "GET").upper()
    path = (path or "/").rstrip("/") or "/"
    mapping: list[tuple[str, str, str]] = [
        ("GET", "/health", "health"),
        ("GET", "/ready", "ready"),
        ("GET", "/resilience", "resilience"),
        ("POST", "/resilience/flush", "resilience.flush"),
        ("GET", "/status", "status"),
        ("GET", "/api", "api"),
        ("GET", "/public/payment-success", "public.payment_success"),
        ("GET", "/public/payment-cancelled", "public.payment_cancelled"),
        ("GET", "/billing/plans", "billing.plans"),
        ("POST", "/billing/checkout", "billing.checkout"),
        ("POST", "/api/checkout", "billing.checkout"),
        ("POST", "/billing/portal", "billing.portal"),
        ("POST", "/billing_portal/sessions", "billing.portal"),
        ("GET", "/billing/stats", "billing.stats"),
        ("GET", "/dashboard", "dashboard"),
        ("POST", "/tenants", "tenants.create"),
        ("GET", "/tenants", "tenants.list"),
        ("POST", "/clients", "clients.create"),
        ("GET", "/clients", "clients.list"),
        ("POST", "/invoices", "invoices.create"),
        ("GET", "/invoices", "invoices.list"),
        ("POST", "/payments", "payments.create"),
        ("GET", "/payments", "payments.list"),
        ("POST", "/expenses", "expenses.create"),
        ("GET", "/expenses/categories", "expenses.categories"),
        ("GET", "/expenses", "expenses.list"),
        ("GET", "/reports/overview", "reports.overview"),
        ("GET", "/reports/aging", "reports.aging"),
        ("GET", "/reports/profit-loss", "reports.profit_loss"),
        ("GET", "/reports/monthly-revenue", "reports.monthly_revenue"),
        ("GET", "/reports/revenue-by-client", "reports.revenue_by_client"),
        ("GET", "/reports/clients", "reports.clients"),
        ("GET", "/reports/revenue", "reports.revenue"),
        ("POST", "/ai/invoice-optimization", "ai.invoice_optimization"),
        ("POST", "/ai/late-payment-risk", "ai.late_payment_risk"),
        ("POST", "/admin/migrate-stripe", "admin.migrate_stripe"),
        ("POST", "/webhooks/stripe", "webhooks.stripe"),
        ("GET", "/recurring", "recurring.list"),
        ("POST", "/recurring", "recurring.create"),
        ("GET", "/estimates", "estimates.list"),
        ("POST", "/estimates", "estimates.create"),
        ("GET", "/products", "products.list"),
        ("GET", "/tax-rates", "tax_rates.list"),
        ("GET", "/credits", "credits.list"),
        ("GET", "/activity", "activity.list"),
    ]
    for m, p, key in mapping:
        if method == m and path == p:
            return key
    # Path params
    if method == "GET" and path.startswith("/invoices/") and path.endswith("/pdf"):
        return "invoices.pdf"
    if method == "POST" and path.startswith("/invoices/") and path.endswith("/pdf"):
        return "invoices.pdf"
    if method == "GET" and path.startswith("/invoices/"):
        return "invoices.get"
    if method == "PATCH" and path.startswith("/invoices/"):
        return "invoices.update"
    if method == "GET" and path.startswith("/estimates/"):
        return "estimates.get"
    if method == "POST" and "/line_items" in path and path.startswith("/estimates/"):
        return "estimates.line_items"
    if method == "POST" and path.endswith("/send") and path.startswith("/estimates/"):
        return "estimates.send"
    if method == "POST" and path.endswith("/approve") and path.startswith("/estimates/"):
        return "estimates.approve"
    if method == "POST" and path.endswith("/convert_to_invoice") and path.startswith("/estimates/"):
        return "estimates.convert"
    return "unknown.write"


def path_auth_dependency():
    """App-level dependency: resolve path → endpoint and enforce authz."""

    def _dependency(
        request: Request,
        x_echo_api_key: str | None = Header(default=None, alias="X-Echo-API-Key"),
    ) -> dict[str, Any]:
        endpoint = resolve_endpoint(request.method, request.url.path)
        tier = ENDPOINT_AUTH.get(endpoint, AUTH_WRITE)
        if tier == AUTH_WEBHOOK:
            return {
                "authenticated": False,
                "tier": AUTH_WEBHOOK,
                "principal": "webhook",
                "endpoint": endpoint,
            }
        return _check_auth(endpoint, x_echo_api_key)

    return _dependency


def verify_stripe_signature(payload: bytes | str, sig_header: str, secret: str) -> bool:
    """Stripe webhook HMAC verification (v1 scheme, 5-minute tolerance)."""
    if not sig_header or not secret:
        return False
    if isinstance(payload, str):
        payload_b = payload.encode("utf-8")
        payload_s = payload
    else:
        payload_b = payload
        payload_s = payload.decode("utf-8", errors="replace")
    try:
        parts = dict(part.split("=", 1) for part in sig_header.split(",") if "=" in part)
        timestamp = parts.get("t", "")
        signatures = [part.split("=", 1)[1] for part in sig_header.split(",") if part.startswith("v1=")]
        if not timestamp or not signatures:
            return False
        if abs(time.time() - int(timestamp)) > 300:
            return False
        signed = timestamp.encode() + b"." + payload_b
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return any(hmac.compare_digest(expected, sig) for sig in signatures)
    except Exception:
        # Fallback single v1 parse (legacy)
        try:
            parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
            ts = parts.get("t")
            v1 = parts.get("v1")
            if not ts or not v1:
                return False
            if abs(int(time.time()) - int(ts)) > 300:
                return False
            signed = f"{ts}.{payload_s}".encode()
            mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
            return hmac.compare_digest(mac, v1)
        except Exception:
            return False


# --- Input validation / escaping -------------------------------------------------


def validate_id(value: str, field: str = "id") -> str:
    value = (value or "").strip()
    if not value or len(value) > 128 or not ID_RE.match(value):
        raise ValueError(f"invalid {field}")
    return value


def validate_optional_id(value: str | None, field: str = "id") -> str | None:
    if value is None or value == "":
        return None
    return validate_id(value, field)


def validate_email(email: str | None) -> str | None:
    if email is None or email == "":
        return None
    email = email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise ValueError("invalid email")
    return email


def validate_name(name: str, field: str = "name", max_len: int = 200) -> str:
    name = (name or "").strip()
    if not name or len(name) > max_len:
        raise ValueError(f"invalid {field}")
    if any(ord(c) < 32 for c in name):
        raise ValueError(f"invalid {field}")
    if re.search(r"[;<>`]", name):
        raise ValueError(f"invalid {field}")
    return name


def validate_description(text: str | None, max_len: int = 4000) -> str | None:
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    if len(text) > max_len:
        raise ValueError("description too long")
    if any(ord(c) < 9 or ord(c) in (11, 12) for c in text if ord(c) < 32):
        raise ValueError("description contains control characters")
    return text


def validate_plan(plan: str) -> str:
    plan = (plan or "").strip().lower()
    if plan not in PLAN_WHITELIST:
        raise ValueError("invalid plan")
    return plan


def validate_status(status: str | None, *, allowed: frozenset[str] | None = None) -> str | None:
    if status is None:
        return None
    status = status.strip().lower()
    whitelist = allowed or INVOICE_STATUS_WHITELIST
    if status not in whitelist:
        raise ValueError("invalid status")
    return status


def validate_currency(currency: str | None) -> str:
    currency = (currency or "USD").strip().upper()
    if not CURRENCY_RE.match(currency):
        raise ValueError("invalid currency")
    return currency


def validate_country(country: str | None) -> str:
    country = (country or "US").strip().upper()
    if not COUNTRY_RE.match(country):
        raise ValueError("invalid country")
    return country


def validate_phone(phone: str | None) -> str | None:
    if phone is None or phone == "":
        return None
    phone = phone.strip()
    if not PHONE_RE.match(phone):
        raise ValueError("invalid phone")
    return phone


def validate_prefix(prefix: str | None) -> str:
    prefix = (prefix or "INV").strip()
    if not PREFIX_RE.match(prefix):
        raise ValueError("invalid invoice_prefix")
    return prefix


def validate_date(value: str | None, field: str = "date") -> str | None:
    if value is None or value == "":
        return None
    value = value.strip()
    if not ISO_DATE_RE.match(value):
        raise ValueError(f"invalid {field}: expected YYYY-MM-DD")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc
    return value


def validate_amount(value: float, field: str = "amount", *, allow_zero: bool = False) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if v != v or v == float("inf") or v == float("-inf"):  # NaN/inf
        raise ValueError(f"invalid {field}")
    if allow_zero:
        if v < 0 or v > 1_000_000_000:
            raise ValueError(f"invalid {field}")
    else:
        if v <= 0 or v > 1_000_000_000:
            raise ValueError(f"invalid {field}")
    return round(v, 4)


def validate_nonneg_amount(value: float, field: str = "amount") -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if v != v or v < 0 or v > 1_000_000_000:
        raise ValueError(f"invalid {field}")
    return round(v, 4)


def validate_percent(value: float, field: str = "percent") -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if v != v or v < 0 or v > 100:
        raise ValueError(f"invalid {field}")
    return round(v, 4)


def validate_quantity(value: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid quantity") from exc
    if v != v or v <= 0 or v > 1_000_000:
        raise ValueError("invalid quantity")
    return round(v, 4)


def validate_method(method: str | None) -> str:
    method = (method or "stripe").strip().lower()
    if method not in METHOD_WHITELIST:
        raise ValueError("invalid payment method")
    return method


def validate_frequency(freq: str | None) -> str:
    freq = (freq or "monthly").strip().lower()
    if freq not in FREQUENCY_WHITELIST:
        raise ValueError("invalid frequency")
    return freq


def validate_category(category: str | None) -> str:
    category = (category or "general").strip()
    if not category or not CATEGORY_RE.match(category):
        raise ValueError("invalid category")
    return category


def validate_limit(limit: int, default: int = 50, max_limit: int = 500) -> int:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = default
    return max(1, min(limit, max_limit))


def validate_json_object(payload: dict[str, Any] | None, *, max_keys: int = 64, max_depth: int = 4) -> dict[str, Any] | None:
    """Validate external JSON object for size/shape; reject deep or huge payloads."""
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    if len(payload) > max_keys:
        raise ValueError("payload has too many keys")

    def _walk(obj: Any, depth: int) -> None:
        if depth > max_depth:
            raise ValueError("payload too deeply nested")
        if isinstance(obj, dict):
            if len(obj) > max_keys:
                raise ValueError("payload object too large")
            for k, v in obj.items():
                if not isinstance(k, str) or len(k) > 128:
                    raise ValueError("invalid payload key")
                _walk(v, depth + 1)
        elif isinstance(obj, list):
            if len(obj) > 256:
                raise ValueError("payload array too large")
            for item in obj:
                _walk(item, depth + 1)
        elif isinstance(obj, str):
            if len(obj) > 8000:
                raise ValueError("payload string too long")
        elif isinstance(obj, (int, float, bool)) or obj is None:
            return
        else:
            raise ValueError("payload contains unsupported type")

    _walk(payload, 0)
    # Round-trip to ensure pure JSON-serializable content
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("payload is not JSON-serializable") from exc
    return payload


def sanitize_like_pattern(value: str) -> str:
    """Escape SQL LIKE wildcards in user-provided search fragments."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def escape_html(value: str | None) -> str:
    """Escape untrusted text for HTML response bodies."""
    return html.escape(value or "", quote=True)


def assert_tenant_access(
    cur,
    tenant_id: str,
    *,
    require_exists: bool = False,
) -> None:
    """Optional tenant existence gate (parameterized). Service API-key already enforces authz tier."""
    tenant_id = validate_id(tenant_id, "tenant_id")
    if not require_exists:
        return
    cur.execute("SELECT 1 FROM echo_invoice.tenants WHERE id=%s LIMIT 1", (tenant_id,))
    if not cur.fetchone():
        raise HTTPException(404, "tenant not found")


def scan_for_hardcoded_secrets(source: str) -> list[str]:
    """Static scan helper for tests — detect obvious secret literals in source."""
    findings: list[str] = []
    patterns = [
        (r'password\s*=\s*["\']echo["\']', "hardcoded PG password"),
        (r'password\s*:\s*["\']echo["\']', "hardcoded PG password"),
        (r'get\(["\']PGPASSWORD["\']\s*,\s*["\']echo["\']\)', "hardcoded PG password default"),
        (r"sk_live_[a-zA-Z0-9]{20,}", "stripe live key"),
        (r"whsec_[a-zA-Z0-9]{20,}", "stripe webhook secret"),
        (r'api_key\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "hardcoded api key literal"),
        (r'dev-invoice-hmac-change-me', "hardcoded HMAC default"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, source):
            findings.append(label)
    return findings


def scan_for_unsafe_sql(source: str) -> list[str]:
    """Detect non-parameterized SQL construction patterns in app source."""
    findings: list[str] = []
    patterns = [
        (r'execute\s*\(\s*f["\']', "f-string SQL execute"),
        (r'execute\s*\(\s*["\'][^"\']*%s[^"\']*["\']\s*%\s*\(', "legacy % formatting SQL"),
        (r'execute\s*\(\s*["\'].*\+.*["\']', "string-concat SQL"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, source):
            findings.append(label)
    return findings


def all_endpoint_keys() -> frozenset[str]:
    return frozenset(ENDPOINT_AUTH.keys())

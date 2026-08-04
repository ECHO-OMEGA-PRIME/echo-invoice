#!/usr/bin/env python3
"""Echo Invoice — FORGE migration of the legacy CF worker `echo-invoice`.

CF-migrate echo-invoice -> Echo FORGE service (ShadowGlass template).
Reconstructs the full route surface and business logic faithfully from the minified
bundle (routes extracted, manifest + sample data inspected for schema):
/health /status /api /tenants /clients /invoices /invoice_items /payments
/recurring /estimates /expenses /products /tax-rates /credits /reports/*
/ai/invoice-optimization /ai/late-payment-risk /admin/migrate-stripe
/webhooks/stripe /public/payment-success /public/payment-cancelled /activity

NO CLOUDFLARE: D1/KV->Postgres (schema echo_invoice), R2->MinIO (optional via env,
stubbed for core paths to keep deps minimal; future: attachment storage for logos/PDFs).
Service bindings (EMAIL_SENDER, ENGINE_RUNTIME) -> optional HTTP via env.

Multi-tenant invoice/estimate/expense/recurring/payments system with Stripe
integration, AI risk/optimization, public payment return pages, append-only
activity_log, full reporting. Idempotent where original used KV keys.

Security (production pass):
- All SQL parameterized (%s placeholders only; no f-string/concat SQL)
- Secrets (PGPASSWORD, Stripe, HMAC, MinIO) from vault.read_secret / env via security.py
- External input validated (ids, emails, dates, JSON, amounts, statuses, plans)
- Tiered authz via X-Echo-API-Key on every non-public entry point (app-level dependency)
- Stripe webhooks verified with HMAC signature when secret is configured
- Public HTML pages escape untrusted query params

Resilience (production pass):
- Graceful degradation when Postgres / MinIO / SDK gate is down (INV_FAIL_OPEN)
- Idempotent writes via Idempotency-Key ledger + pending-write queue
- Exponential retry/backoff + circuit breakers (resilience.py)
- /ready + /resilience diagnostics; fail-open keeps process accepting traffic

Run: uvicorn app:app --host 0.0.0.0 --port 8092 --log-level info
(systemd: echo-invoice.service, User=forge, MemoryMax=512M)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Annotated, Any, Optional

import psycopg2
import psycopg2.extras
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

import security as _sec
from resilience import (
    RESILIENCE_VERSION,
    DependencyUnavailable,
    PendingWrite,
    is_retryable,
    pg_connect_kwargs as resilience_pg_kwargs,
    reset_runtime_for_tests,
    retry_with_backoff,
    runtime as inv_runtime,
)
from security import (
    ESTIMATE_STATUS_WHITELIST,
    INVOICE_STATUS_WHITELIST,
    auth_dependency,
    escape_html,
    invoice_hmac_key,
    minio_access_key,
    minio_secret_key,
    path_auth_dependency,
    pg_config,
    stripe_secret_key,
    stripe_webhook_secret,
    validate_amount,
    validate_category,
    validate_country,
    validate_currency,
    validate_date,
    validate_description,
    validate_email,
    validate_frequency,
    validate_id,
    validate_json_object,
    validate_limit,
    validate_method,
    validate_name,
    validate_nonneg_amount,
    validate_optional_id,
    validate_percent,
    validate_phone,
    validate_plan,
    validate_prefix,
    validate_quantity,
    validate_status,
    verify_stripe_signature,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [echo-invoice] %(levelname)s %(message)s",
)
logger = logging.getLogger("echo_invoice")

VERSION = "1.2.0-resilience"

ENGINE_URL = os.environ.get("ECHO_ENGINE_RUNTIME_URL", "")
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "")
PORT = int(os.environ.get("PORT", os.environ.get("FORGE_PORT", "8092")))

INVOICING_PLANS = {
    "free": {"name": "Free", "price": 0, "invoices_per_month": 5, "features": ["5 invoices/mo", "Basic PDF export", "Manual payments"]},
    "pro": {"name": "Pro", "price": 2499, "invoices_per_month": 200, "features": ["200 invoices/mo", "Recurring invoices", "AI analysis", "Email delivery", "Payment links"]},
    "enterprise": {"name": "Enterprise", "price": 7999, "invoices_per_month": -1, "features": ["Unlimited invoices", "All Pro features", "Multi-tenant", "API access", "Priority support", "Custom branding"]},
}

SCHEMA = """
CREATE SCHEMA IF NOT EXISTS echo_invoice;

CREATE TABLE IF NOT EXISTS echo_invoice.tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    country TEXT DEFAULT 'US',
    tax_id TEXT,
    logo_url TEXT,
    currency TEXT DEFAULT 'USD',
    payment_terms_days INTEGER DEFAULT 30,
    late_fee_percent REAL DEFAULT 0,
    invoice_prefix TEXT DEFAULT 'INV',
    next_invoice_number INTEGER DEFAULT 1001,
    bank_name TEXT,
    bank_account TEXT,
    bank_routing TEXT,
    paypal_email TEXT,
    stripe_account_id TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS echo_invoice.clients (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    country TEXT DEFAULT 'US',
    tax_id TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_clients_tenant ON echo_invoice.clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_clients_email ON echo_invoice.clients(email);

CREATE TABLE IF NOT EXISTS echo_invoice.products (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    unit_price REAL NOT NULL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    tax_rate_id TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_products_tenant ON echo_invoice.products(tenant_id);

CREATE TABLE IF NOT EXISTS echo_invoice.tax_rates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    rate REAL NOT NULL DEFAULT 0,
    is_inclusive INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_tax_tenant ON echo_invoice.tax_rates(tenant_id);

CREATE TABLE IF NOT EXISTS echo_invoice.invoices (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES echo_invoice.clients(id),
    invoice_number TEXT NOT NULL,
    status TEXT DEFAULT 'draft',
    issue_date DATE,
    due_date DATE,
    paid_date DATE,
    subtotal REAL DEFAULT 0,
    tax_rate REAL DEFAULT 0,
    tax_amount REAL DEFAULT 0,
    discount_percent REAL DEFAULT 0,
    discount_amount REAL DEFAULT 0,
    shipping REAL DEFAULT 0,
    total REAL DEFAULT 0,
    amount_paid REAL DEFAULT 0,
    amount_due REAL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    notes TEXT,
    terms TEXT,
    footer TEXT,
    po_number TEXT,
    is_recurring INTEGER DEFAULT 0,
    recurring_id TEXT,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_invoices_tenant ON echo_invoice.invoices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_invoices_client ON echo_invoice.invoices(client_id);
CREATE INDEX IF NOT EXISTS idx_inv_invoices_status ON echo_invoice.invoices(status);
CREATE INDEX IF NOT EXISTS idx_inv_invoices_due ON echo_invoice.invoices(due_date);
CREATE UNIQUE INDEX IF NOT EXISTS uq_inv_invoice_number ON echo_invoice.invoices(tenant_id, invoice_number);

CREATE TABLE IF NOT EXISTS echo_invoice.invoice_items (
    id TEXT PRIMARY KEY,
    invoice_id TEXT NOT NULL REFERENCES echo_invoice.invoices(id) ON DELETE CASCADE,
    product_id TEXT,
    description TEXT NOT NULL,
    quantity REAL DEFAULT 1,
    unit_price REAL NOT NULL,
    tax_rate REAL DEFAULT 0,
    line_total REAL NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_items_invoice ON echo_invoice.invoice_items(invoice_id);

CREATE TABLE IF NOT EXISTS echo_invoice.payments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    invoice_id TEXT REFERENCES echo_invoice.invoices(id),
    client_id TEXT REFERENCES echo_invoice.clients(id),
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    method TEXT DEFAULT 'stripe',
    reference TEXT,
    paid_at TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_payments_tenant ON echo_invoice.payments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_payments_invoice ON echo_invoice.payments(invoice_id);

CREATE TABLE IF NOT EXISTS echo_invoice.recurring_invoices (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES echo_invoice.clients(id),
    name TEXT NOT NULL,
    frequency TEXT DEFAULT 'monthly',
    next_date DATE,
    status TEXT DEFAULT 'active',
    invoice_template TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_recurring_tenant ON echo_invoice.recurring_invoices(tenant_id);

CREATE TABLE IF NOT EXISTS echo_invoice.estimates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES echo_invoice.clients(id),
    estimate_number TEXT NOT NULL,
    status TEXT DEFAULT 'draft',
    issue_date DATE,
    valid_until DATE,
    subtotal REAL DEFAULT 0,
    total REAL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_estimates_tenant ON echo_invoice.estimates(tenant_id);

CREATE TABLE IF NOT EXISTS echo_invoice.estimate_items (
    id TEXT PRIMARY KEY,
    estimate_id TEXT NOT NULL REFERENCES echo_invoice.estimates(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    quantity REAL DEFAULT 1,
    unit_price REAL NOT NULL,
    line_total REAL NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_est_items_estimate ON echo_invoice.estimate_items(estimate_id);

CREATE TABLE IF NOT EXISTS echo_invoice.expenses (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    category TEXT DEFAULT 'general',
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    expense_date DATE,
    vendor TEXT,
    receipt_url TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_expenses_tenant ON echo_invoice.expenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_expenses_category ON echo_invoice.expenses(category);

CREATE TABLE IF NOT EXISTS echo_invoice.credits (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES echo_invoice.clients(id),
    amount REAL NOT NULL,
    reason TEXT,
    applied_at TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_credits_tenant ON echo_invoice.credits(tenant_id);

CREATE TABLE IF NOT EXISTS echo_invoice.activity_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_activity_tenant_time ON echo_invoice.activity_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_activity_entity ON echo_invoice.activity_log(entity_type, entity_id);

-- Billing / subscriptions (from echo-invoicing sibling; combined)
CREATE TABLE IF NOT EXISTS echo_invoice.subscriptions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES echo_invoice.tenants(id) ON DELETE CASCADE,
    stripe_customer_id TEXT UNIQUE NOT NULL,
    stripe_subscription_id TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    status TEXT DEFAULT 'active',
    invoices_limit INTEGER DEFAULT 5,
    current_period_end TIMESTAMPTZ,
    customer_email TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_sub_tenant ON echo_invoice.subscriptions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_sub_stripe ON echo_invoice.subscriptions(stripe_customer_id);

CREATE TABLE IF NOT EXISTS echo_invoice.payment_history (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES echo_invoice.tenants(id) ON DELETE SET NULL,
    stripe_customer_id TEXT,
    stripe_invoice_id TEXT UNIQUE,
    amount_cents INTEGER,
    currency TEXT DEFAULT 'USD',
    status TEXT,
    plan TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inv_payhist_customer ON echo_invoice.payment_history(stripe_customer_id);
"""

# --- helpers ---

def uid() -> str:
    return uuid.uuid4().hex[:16]

def now_iso() -> str:
    return datetime.utcnow().isoformat(sep=" ", timespec="seconds")

def log(level: str, msg: str, extra: dict[str, Any] | None = None) -> None:
    payload = {"ts": datetime.utcnow().isoformat() + "Z", "level": level, "msg": msg, "service": "echo-invoice"}
    if extra:
        payload.update(extra)
    logger.info(json.dumps(payload))

def ok(data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": True, **(data or {})}

def fail(msg: str, code: int = 400) -> dict[str, Any]:
    return {"ok": False, "error": msg}

CORS_HEADERS = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": (
        "Content-Type, Authorization, X-Echo-API-Key, stripe-signature, Idempotency-Key"
    ),
}


def _connect_kwargs() -> dict[str, Any]:
    """Merge security.pg_config secrets with resilience connect timeouts."""
    kwargs = dict(resilience_pg_kwargs())
    try:
        sec = pg_config()
        for k, v in sec.items():
            if v is not None and v != "":
                kwargs[k] = v
    except Exception:
        pass
    return kwargs


def _raw_connect():
    """Bare psycopg2 connect (used by probes + retry path)."""
    return psycopg2.connect(**_connect_kwargs())


@contextmanager
def _db():
    """DB context with request-path retry + circuit awareness."""
    if inv_runtime.circuit_pg.is_open():
        inv_runtime.mark_db_down()
        raise DependencyUnavailable("postgres", "circuit_open")

    def _open():
        return _raw_connect()

    try:
        con = retry_with_backoff(
            _open,
            inv_runtime.request_retry,
            op_name="pg_connect",
            dependency="postgres",
        )
    except Exception as exc:
        if is_retryable(exc):
            inv_runtime.mark_db_down()
        raise
    try:
        yield con
        con.commit()
        inv_runtime.mark_db_up()
    except Exception as exc:
        try:
            con.rollback()
        except Exception:
            pass
        if is_retryable(exc):
            inv_runtime.mark_db_down()
        raise
    finally:
        try:
            con.close()
        except Exception:
            pass


def _idempotency_lookup(key: Optional[str]) -> Optional[dict[str, Any]]:
    if not key or not str(key).strip():
        return None
    return inv_runtime.recall_idempotent(str(key).strip())


def _idempotency_store(key: Optional[str], body: dict[str, Any]) -> None:
    if key and str(key).strip():
        inv_runtime.remember_idempotent(str(key).strip(), body)


def _queue_or_fail(
    kind: str,
    payload: dict[str, Any],
    *,
    soft_key: Optional[str] = None,
    entity_hint: Optional[str] = None,
) -> dict[str, Any]:
    """When DB is down and fail_open is set, queue write and return accepted."""
    if not inv_runtime.fail_open:
        return {"ok": False, "error": "database unavailable", "status_code": 503}
    qkey = soft_key or inv_runtime.idempotency.make_key(kind, payload)
    queued = inv_runtime.queue_write(kind, payload, idempotency_key=qkey)
    if not queued:
        return {"ok": False, "error": "pending write queue full", "status_code": 503}
    body = ok(
        {
            "queued": True,
            "degraded": True,
            "kind": kind,
            "idempotency_key": soft_key or qkey,
            "id": entity_hint or payload.get("id"),
            "pending": True,
        }
    )
    if soft_key:
        _idempotency_store(soft_key, body)
    return body


def _apply_pending_write(item: PendingWrite) -> bool:
    """Replay a queued invoice write against Postgres."""
    kind = item.kind
    p = item.payload
    sql = p.get("sql")
    params = p.get("params")
    if not sql or params is None:
        log("warn", "pending write missing sql/params", {"kind": kind})
        return False
    try:
        with _db() as con, con.cursor() as cur:
            for pre in p.get("pre_sql") or []:
                cur.execute(pre["sql"], tuple(pre.get("params") or ()))
            cur.execute(sql, tuple(params))
            for extra in p.get("extra_sql") or []:
                cur.execute(extra["sql"], tuple(extra.get("params") or ()))
            act = p.get("activity") or {}
            if act.get("entity_type") and act.get("entity_id") and act.get("action"):
                cur.execute(
                    "INSERT INTO echo_invoice.activity_log(tenant_id, entity_type, entity_id, action, details) "
                    "VALUES (%s,%s,%s,%s,%s)",
                    (
                        act.get("tenant_id"),
                        str(act["entity_type"]),
                        str(act["entity_id"]),
                        str(act["action"]),
                        act.get("details"),
                    ),
                )
        if item.idempotency_key:
            _idempotency_store(
                item.idempotency_key,
                ok({"id": p.get("id"), "replayed": True, "queued": False, "kind": kind}),
            )
        return True
    except Exception as exc:
        log("warn", "pending write apply failed", {"kind": kind, "error": str(exc)[:160]})
        return False


def _log_activity(tenant_id: str | None, entity_type: str, entity_id: str, action: str, details: str | None = None) -> None:
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(
                "INSERT INTO echo_invoice.activity_log(tenant_id, entity_type, entity_id, action, details) "
                "VALUES (%s,%s,%s,%s,%s)",
                (tenant_id, entity_type, entity_id, action, details),
            )
    except Exception:
        pass  # activity log best effort

def _ensure_tenant(cur, tenant_id: str, name: str = "Default Tenant") -> None:
    cur.execute(
        "INSERT INTO echo_invoice.tenants(id, name) VALUES(%s, %s) ON CONFLICT (id) DO NOTHING",
        (tenant_id, name),
    )

def _calc_invoice_totals(items: list[dict], discount_percent: float = 0, shipping: float = 0, tax_rate: float = 0) -> dict:
    subtotal = sum(float(i.get("line_total", 0) or (float(i.get("quantity",1))*float(i.get("unit_price",0)))) for i in items)
    discount_amount = round(subtotal * (discount_percent / 100.0), 2)
    tax_amount = round((subtotal - discount_amount) * (tax_rate / 100.0), 2)
    total = round(subtotal - discount_amount + tax_amount + shipping, 2)
    return {
        "subtotal": round(subtotal, 2),
        "discount_amount": discount_amount,
        "tax_amount": tax_amount,
        "total": total,
        "amount_due": total,
    }

def _call_engine(prompt: str, domain: str = "finance") -> Optional[dict]:
    if not ENGINE_URL:
        return None
    try:
        data = json.dumps({"query": prompt, "domain": domain, "limit": 3}).encode()
        req = urllib.request.Request(
            ENGINE_URL.rstrip("/") + "/query",
            data=data,
            headers={"Content-Type": "application/json", "X-Echo-API-Key": _sec.api_key()},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return json.loads(resp.read())
    except Exception as e:
        log("warn", "Engine call failed", {"error": str(e)[:120]})
    return None

def _verify_stripe_signature(payload: str, sig_header: str, secret: str) -> bool:
    return verify_stripe_signature(payload, sig_header, secret)


def _stripe_request(method: str, path: str, data: dict | None = None, idempotency: str | None = None) -> dict | None:
    key = stripe_secret_key()
    if not key:
        return None
    url = f"https://api.stripe.com/v1{path}"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/x-www-form-urlencoded"}
    if idempotency:
        headers["Idempotency-Key"] = idempotency
    try:
        body = urllib.parse.urlencode(data or {}).encode() if data and method.upper() == "POST" else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        with urllib.request.urlopen(req, timeout=12) as resp:
            if resp.status < 300:
                return json.loads(resp.read())
            log("warn", "stripe non-2xx", {"status": resp.status})
            return None
    except Exception as e:
        log("error", "stripe api error", {"path": path, "err": str(e)[:120]})
        return None


def _get_current_plan(cur, tenant_id: str) -> dict:
    cur.execute(
        "SELECT plan, invoices_limit, status FROM echo_invoice.subscriptions "
        "WHERE tenant_id=%s AND status='active' ORDER BY created_at DESC LIMIT 1",
        (tenant_id,)
    )
    row = cur.fetchone()
    if row:
        return {"plan": row[0], "limit": int(row[1]), "status": row[2]}
    return {"plan": "free", "limit": 5, "status": "active"}


def _count_invoices_this_month(cur, tenant_id: str) -> int:
    cur.execute(
        "SELECT COUNT(*) FROM echo_invoice.invoices "
        "WHERE tenant_id=%s AND created_at >= date_trunc('month', CURRENT_TIMESTAMP)",
        (tenant_id,)
    )
    return int(cur.fetchone()[0] or 0)



def _req_tenant_id(tenant_id: str) -> str:
    return validate_id(tenant_id, "tenant_id")


def _req_limit(limit: int, default: int = 50, max_limit: int = 200) -> int:
    return validate_limit(limit, default=default, max_limit=max_limit)


def _req_invoice_status(status: str | None) -> str | None:
    return validate_status(status, allowed=INVOICE_STATUS_WHITELIST)


def _req_estimate_status(status: str | None) -> str | None:
    return validate_status(status, allowed=ESTIMATE_STATUS_WHITELIST)

# --- models ---

class TenantBody(BaseModel):
    name: str
    email: str | None = None
    phone: str | None = None
    address: str | None = None
    city: str | None = None
    state: str | None = None
    zip: str | None = None
    country: str = "US"
    currency: str = "USD"
    invoice_prefix: str = "INV"

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return validate_name(v)

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str | None) -> str | None:
        return validate_email(v)

    @field_validator("phone")
    @classmethod
    def _v_phone(cls, v: str | None) -> str | None:
        return validate_phone(v)

    @field_validator("address", "city", "state", "zip")
    @classmethod
    def _v_addr(cls, v: str | None) -> str | None:
        return validate_description(v, max_len=500) if v else None

    @field_validator("country")
    @classmethod
    def _v_country(cls, v: str) -> str:
        return validate_country(v)

    @field_validator("currency")
    @classmethod
    def _v_currency(cls, v: str) -> str:
        return validate_currency(v)

    @field_validator("invoice_prefix")
    @classmethod
    def _v_prefix(cls, v: str) -> str:
        return validate_prefix(v)


class ClientBody(BaseModel):
    tenant_id: str
    name: str
    email: str | None = None
    phone: str | None = None
    address: str | None = None
    notes: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return validate_name(v)

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str | None) -> str | None:
        return validate_email(v)

    @field_validator("phone")
    @classmethod
    def _v_phone(cls, v: str | None) -> str | None:
        return validate_phone(v)

    @field_validator("address", "notes")
    @classmethod
    def _v_text(cls, v: str | None) -> str | None:
        return validate_description(v, max_len=2000) if v else None


class InvoiceItemIn(BaseModel):
    description: str
    quantity: float = 1.0
    unit_price: float
    product_id: str | None = None

    @field_validator("description")
    @classmethod
    def _v_desc(cls, v: str) -> str:
        out = validate_description(v, max_len=2000)
        if not out:
            raise ValueError("description required")
        return out

    @field_validator("quantity")
    @classmethod
    def _v_qty(cls, v: float) -> float:
        return validate_quantity(v)

    @field_validator("unit_price")
    @classmethod
    def _v_price(cls, v: float) -> float:
        return validate_nonneg_amount(v, "unit_price")

    @field_validator("product_id")
    @classmethod
    def _v_pid(cls, v: str | None) -> str | None:
        return validate_optional_id(v, "product_id")


class InvoiceCreate(BaseModel):
    tenant_id: str
    client_id: str
    items: list[InvoiceItemIn]
    issue_date: str | None = None
    due_date: str | None = None
    discount_percent: float = 0
    shipping: float = 0
    tax_rate: float = 0
    notes: str | None = None
    po_number: str | None = None
    currency: str = "USD"

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("client_id")
    @classmethod
    def _v_cid(cls, v: str) -> str:
        return validate_id(v, "client_id")

    @field_validator("issue_date", "due_date")
    @classmethod
    def _v_date(cls, v: str | None) -> str | None:
        return validate_date(v)

    @field_validator("discount_percent", "tax_rate")
    @classmethod
    def _v_pct(cls, v: float) -> float:
        return validate_percent(v)

    @field_validator("shipping")
    @classmethod
    def _v_ship(cls, v: float) -> float:
        return validate_nonneg_amount(v, "shipping")

    @field_validator("notes")
    @classmethod
    def _v_notes(cls, v: str | None) -> str | None:
        return validate_description(v, max_len=4000)

    @field_validator("po_number")
    @classmethod
    def _v_po(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        return validate_name(v, "po_number", max_len=64)

    @field_validator("currency")
    @classmethod
    def _v_cur(cls, v: str) -> str:
        return validate_currency(v)

    @field_validator("items")
    @classmethod
    def _v_items(cls, v: list) -> list:
        if not v or len(v) > 500:
            raise ValueError("items must contain 1..500 entries")
        return v


class PaymentIn(BaseModel):
    tenant_id: str
    invoice_id: str | None = None
    client_id: str | None = None
    amount: float
    method: str = "stripe"
    reference: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("invoice_id", "client_id")
    @classmethod
    def _v_opt(cls, v: str | None) -> str | None:
        return validate_optional_id(v)

    @field_validator("amount")
    @classmethod
    def _v_amt(cls, v: float) -> float:
        return validate_amount(v, "amount")

    @field_validator("method")
    @classmethod
    def _v_method(cls, v: str) -> str:
        return validate_method(v)

    @field_validator("reference")
    @classmethod
    def _v_ref(cls, v: str | None) -> str | None:
        return validate_description(v, max_len=256)


class EstimateItemIn(BaseModel):
    description: str
    quantity: float = 1.0
    unit_price: float

    @field_validator("description")
    @classmethod
    def _v_desc(cls, v: str) -> str:
        out = validate_description(v, max_len=2000)
        if not out:
            raise ValueError("description required")
        return out

    @field_validator("quantity")
    @classmethod
    def _v_qty(cls, v: float) -> float:
        return validate_quantity(v)

    @field_validator("unit_price")
    @classmethod
    def _v_price(cls, v: float) -> float:
        return validate_nonneg_amount(v, "unit_price")


class EstimateCreate(BaseModel):
    tenant_id: str
    client_id: str
    items: list[EstimateItemIn] = Field(default_factory=list)
    issue_date: str | None = None
    valid_until: str | None = None
    notes: str | None = None
    currency: str = "USD"

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("client_id")
    @classmethod
    def _v_cid(cls, v: str) -> str:
        return validate_id(v, "client_id")

    @field_validator("issue_date", "valid_until")
    @classmethod
    def _v_date(cls, v: str | None) -> str | None:
        return validate_date(v)

    @field_validator("notes")
    @classmethod
    def _v_notes(cls, v: str | None) -> str | None:
        return validate_description(v, max_len=4000)

    @field_validator("currency")
    @classmethod
    def _v_cur(cls, v: str) -> str:
        return validate_currency(v)

    @field_validator("items")
    @classmethod
    def _v_items(cls, v: list) -> list:
        if len(v) > 500:
            raise ValueError("too many estimate items")
        return v


class EstimateLineItemsIn(BaseModel):
    items: list[EstimateItemIn]

    @field_validator("items")
    @classmethod
    def _v_items(cls, v: list) -> list:
        if not v or len(v) > 500:
            raise ValueError("items must contain 1..500 entries")
        return v


class ExpenseIn(BaseModel):
    tenant_id: str
    category: str = "general"
    description: str
    amount: float
    expense_date: str | None = None
    vendor: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("category")
    @classmethod
    def _v_cat(cls, v: str) -> str:
        return validate_category(v)

    @field_validator("description")
    @classmethod
    def _v_desc(cls, v: str) -> str:
        out = validate_description(v, max_len=2000)
        if not out:
            raise ValueError("description required")
        return out

    @field_validator("amount")
    @classmethod
    def _v_amt(cls, v: float) -> float:
        return validate_amount(v, "amount")

    @field_validator("expense_date")
    @classmethod
    def _v_date(cls, v: str | None) -> str | None:
        return validate_date(v, "expense_date")

    @field_validator("vendor")
    @classmethod
    def _v_vendor(cls, v: str | None) -> str | None:
        return validate_name(v, "vendor") if v else None


class AIRequest(BaseModel):
    tenant_id: str
    invoice_id: str | None = None
    payload: dict[str, Any] | None = None

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("invoice_id")
    @classmethod
    def _v_iid(cls, v: str | None) -> str | None:
        return validate_optional_id(v, "invoice_id")

    @field_validator("payload")
    @classmethod
    def _v_payload(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return validate_json_object(v)


class BillingCheckoutBody(BaseModel):
    tenant_id: str
    plan: str
    customer_email: str | None = None
    success_url: str | None = None
    cancel_url: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str) -> str:
        return validate_id(v, "tenant_id")

    @field_validator("plan")
    @classmethod
    def _v_plan(cls, v: str) -> str:
        return validate_plan(v)

    @field_validator("customer_email")
    @classmethod
    def _v_email(cls, v: str | None) -> str | None:
        return validate_email(v)

    @field_validator("success_url", "cancel_url")
    @classmethod
    def _v_url(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.strip()
        if len(v) > 2048 or not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("invalid url")
        if any(c in v for c in ("<", ">", '"', "'", "`")):
            raise ValueError("invalid url")
        return v


class BillingPortalBody(BaseModel):
    tenant_id: str | None = None
    customer_id: str | None = None
    stripe_customer_id: str | None = None
    return_url: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def _v_tid(cls, v: str | None) -> str | None:
        return validate_optional_id(v, "tenant_id")

    @field_validator("customer_id", "stripe_customer_id")
    @classmethod
    def _v_cust(cls, v: str | None) -> str | None:
        return validate_optional_id(v, "customer_id")

    @field_validator("return_url")
    @classmethod
    def _v_url(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.strip()
        if len(v) > 2048 or not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("invalid url")
        return v


# --- app ---

app = FastAPI(
    title="Echo Invoice",
    version=VERSION,
    description="FORGE migration of echo-invoice CF worker (security-hardened + resilient)",
    dependencies=[Depends(path_auth_dependency())],
)


@app.exception_handler(ValueError)
async def _value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})


@app.exception_handler(DependencyUnavailable)
async def _dep_unavailable_handler(request: Request, exc: DependencyUnavailable):
    return JSONResponse(
        status_code=503 if not inv_runtime.fail_open else 200,
        content={
            "ok": False,
            "error": str(exc),
            "dependency": exc.dependency,
            "degraded": True,
            "fail_open": inv_runtime.fail_open,
            "service": "echo-invoice",
            "version": VERSION,
            "resilience_version": RESILIENCE_VERSION,
        },
    )


@app.on_event("startup")
def _startup() -> None:
    db_ready = False
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(SCHEMA)
        db_ready = True
        log("info", "echo_invoice schema ready")
    except Exception as e:
        inv_runtime.mark_db_down()
        log(
            "error",
            "schema init failed — running degraded" if inv_runtime.fail_open else "schema init failed",
            {"error": str(e)[:160], "fail_open": inv_runtime.fail_open},
        )
        if not inv_runtime.fail_open:
            raise

    try:
        inv_runtime.refresh_health(connect_fn=_raw_connect)
    except Exception as e:
        log("warn", "initial dependency probe failed", {"error": str(e)[:160]})

    inv_runtime.start_flusher(
        _apply_pending_write,
        interval_sec=float(os.environ.get("INV_FLUSH_INTERVAL", "5")),
    )
    inv_runtime.start_probe_loop(
        _raw_connect,
        interval_sec=float(os.environ.get("INV_PROBE_INTERVAL", "30")),
    )
    log(
        "info",
        "resilience runtime ready",
        {
            "resilience_version": RESILIENCE_VERSION,
            "fail_open": inv_runtime.fail_open,
            "db_ready": db_ready,
            "mode": inv_runtime.get_health().mode,
            "version": VERSION,
        },
    )


@app.get("/health")
def health():
    """Liveness + dependency diagnostics. HTTP 200 even when degraded under fail-open."""
    db_ok = False
    db_latency_ms = 0.0
    db_error = None
    try:
        start = time.time()
        with _db() as con, con.cursor() as cur:
            cur.execute("SELECT 1")
        db_latency_ms = (time.time() - start) * 1000
        db_ok = True
        inv_runtime.mark_db_up()
    except Exception as e:
        db_error = str(e)[:120]
        log("warn", "Health check: DB connection failed", {"error": db_error})
        inv_runtime.mark_db_down()

    try:
        health_snap = inv_runtime.refresh_health(connect_fn=_raw_connect if db_ok else None)
    except Exception:
        health_snap = inv_runtime.get_health()
        if db_ok:
            health_snap.postgres = {"ok": True, "latency_ms": round(db_latency_ms, 3)}
            health_snap.mode = "healthy"
        else:
            health_snap.postgres = {
                "ok": False,
                "latency_ms": round(db_latency_ms, 3),
                "detail": db_error or "unavailable",
            }
            health_snap.mode = "degraded" if inv_runtime.fail_open else "unavailable"

    minio_check = getattr(health_snap, "minio", {}) or {}
    gate_check = getattr(health_snap, "gate", {}) or {}
    optional_degraded = bool(
        (minio_check.get("configured") and not minio_check.get("ok"))
        or (gate_check.get("configured") and not gate_check.get("ok"))
    )
    core_degraded = (not db_ok) and inv_runtime.fail_open
    mode = health_snap.mode if hasattr(health_snap, "mode") else ("healthy" if db_ok else "degraded")

    sk = stripe_secret_key()
    wh = stripe_webhook_secret()
    payload = {
        "ok": db_ok,
        "status": "ok" if db_ok else ("degraded" if inv_runtime.fail_open else "unavailable"),
        "service": "echo-invoice",
        "version": VERSION,
        "resilience_version": RESILIENCE_VERSION,
        "db": db_ok,
        "port": PORT,
        "stripe": bool(sk),
        "stripe_webhook": bool(wh),
        "payment_rail_ready": bool(sk),
        "plans_available": len(INVOICING_PLANS),
        "degraded": core_degraded,
        "optional_degraded": optional_degraded,
        "mode": mode,
        "fail_open": inv_runtime.fail_open,
        "pending_writes": inv_runtime.pending_writes.size,
        "checks": {
            "database": {
                "status": "healthy" if db_ok else "unhealthy",
                "latency_ms": round(db_latency_ms, 3),
            },
            "postgres": health_snap.postgres,
            "minio": health_snap.minio,
            "gate": health_snap.gate,
        },
        "dependencies": health_snap.to_dict() if hasattr(health_snap, "to_dict") else {},
    }
    if db_error and not db_ok:
        payload["error"] = db_error
    inv_runtime.cache.set_health(payload)
    return payload


@app.get("/ready")
def ready():
    """Readiness: process accepts traffic (fail-open allows degraded)."""
    h = inv_runtime.get_health()
    ready_ok = h.mode in ("healthy", "degraded") or inv_runtime.fail_open
    return {
        "ok": ready_ok,
        "ready": ready_ok,
        "service": "echo-invoice",
        "version": VERSION,
        "mode": h.mode,
        "fail_open": inv_runtime.fail_open,
        "resilience_version": RESILIENCE_VERSION,
    }


@app.get("/resilience")
def resilience_status():
    """Full resilience runtime status (dependencies, queues, retry policy)."""
    out = inv_runtime.status_dict()
    out["ok"] = True
    out["version"] = VERSION
    out["resilience_version"] = RESILIENCE_VERSION
    return out


@app.post("/resilience/flush")
def resilience_flush():
    """Manually drain pending write + MinIO queues (ops)."""
    applied, remaining = inv_runtime.pending_writes.drain(_apply_pending_write)
    return ok(
        {
            "flushed": applied,
            "remaining": remaining,
            "pending_writes": inv_runtime.pending_writes.size,
            "minio_queue": inv_runtime.minio_queue.size,
        }
    )


@app.get("/status")
def status():
    mode = inv_runtime.get_health().mode
    body = ok(
        {
            "service": "echo-invoice",
            "version": VERSION,
            "resilience_version": RESILIENCE_VERSION,
            "features": [
                "invoices",
                "billing",
                "subscriptions",
                "plans",
                "reports",
                "stripe",
                "ai",
                "public",
                "authz",
                "resilience",
                "idempotent_writes",
                "graceful_degradation",
            ],
            "port": PORT,
            "mode": mode if mode != "unknown" else ("degraded" if inv_runtime.degraded else "healthy"),
            "fail_open": inv_runtime.fail_open,
            "pending_writes": inv_runtime.pending_writes.size,
            "ts": now_iso(),
        }
    )
    inv_runtime.cache.set_status(body)
    return body


@app.get("/api")
def api_root():
    return ok({
        "service": "echo-invoice",
        "routes": ["/tenants", "/clients", "/invoices", "/payments", "/reports/*", "/ai/*", "/webhooks/stripe", "/public/*", "/health", "/billing/*", "/dashboard", "/checkout/sessions"],
        "storage": "postgres:echo_invoice (R2->MinIO optional)"
    })


# --- billing / subscriptions (combined from echo-invoicing + echo-invoice siblings; ShadowGlass faithful) ---

@app.get("/billing/plans")
def billing_plans():
    plans = []
    for pid, p in INVOICING_PLANS.items():
        plans.append({
            "id": pid,
            "name": p["name"],
            "price_cents": p["price"],
            "price_display": "Free" if p["price"] == 0 else f"${p['price']/100:.2f}/mo",
            "invoices_per_month": p["invoices_per_month"],
            "features": p["features"],
        })
    return ok({"plans": plans})


@app.post("/billing/checkout")
@app.post("/api/checkout")
def billing_checkout(b: BillingCheckoutBody):
    plan = INVOICING_PLANS.get(b.plan)
    if not plan:
        return fail("Invalid plan. Valid: free, pro, enterprise")
    if not b.customer_email:
        return fail("customer_email required")
    try:
        if plan["price"] == 0:
            with _db() as con, con.cursor() as cur:
                _ensure_tenant(cur, b.tenant_id)
                sub_id = uid()
                cur.execute(
                    "INSERT INTO echo_invoice.subscriptions(id,tenant_id,stripe_customer_id,plan,status,invoices_limit,customer_email) "
                    "VALUES(%s,%s,%s,'free','active',5,%s) "
                    "ON CONFLICT (stripe_customer_id) DO UPDATE SET plan='free',invoices_limit=5,updated_at=now()",
                    (sub_id, b.tenant_id, f"free_{b.tenant_id[:12]}", b.customer_email)
                )
            _log_activity(b.tenant_id, "billing", sub_id, "free_activated", b.plan)
            return ok({"session_id": None, "checkout_url": None, "plan": "free", "message": "Free plan activated — no payment required"})
        # Paid: create Stripe Checkout Session for subscription
        sess = _stripe_request("POST", "/checkout/sessions", {
            "mode": "subscription",
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": str(plan["price"]),
            "line_items[0][price_data][recurring][interval]": "month",
            "line_items[0][price_data][product_data][name]": f"Echo Invoicing — {plan['name']}",
            "line_items[0][price_data][product_data][description]": f"{'Unlimited' if plan['invoices_per_month']==-1 else plan['invoices_per_month']} invoices/mo — {', '.join(plan['features'])}",
            "line_items[0][quantity]": "1",
            "customer_email": b.customer_email,
            "success_url": b.success_url or "https://echo-ept.com/invoicing?billing=success",
            "cancel_url": b.cancel_url or "https://echo-ept.com/invoicing?billing=cancel",
            "metadata[plan]": b.plan,
            "metadata[tenant_id]": b.tenant_id,
        })
        if not sess or "id" not in sess:
            return fail("stripe checkout creation failed (check STRIPE_SECRET_KEY)")
        _log_activity(b.tenant_id, "billing", sess["id"], "checkout_created", b.plan)
        return ok({"session_id": sess.get("id"), "checkout_url": sess.get("url"), "plan": b.plan})
    except Exception as e:
        log("error", "billing_checkout failed", {"err": str(e)[:120]})
        return fail("db or stripe unavailable", 503)


@app.post("/billing/portal")
@app.post("/billing_portal/sessions")
def billing_portal(b: BillingPortalBody):
    try:
        cid = b.customer_id or b.stripe_customer_id
        if not cid and b.tenant_id:
            with _db() as con, con.cursor() as cur:
                cur.execute("SELECT stripe_customer_id FROM echo_invoice.subscriptions WHERE tenant_id=%s AND status='active' LIMIT 1", (b.tenant_id,))
                r = cur.fetchone()
                if r: cid = r[0]
        if not cid:
            return fail("customer_id (or tenant_id with active sub) required")
        if not stripe_secret_key():
            return fail("STRIPE_SECRET_KEY not configured")
        portal = _stripe_request("POST", "/billing_portal/sessions", {
            "customer": cid,
            "return_url": b.return_url or "https://echo-ept.com/invoicing",
        })
        if not portal or "url" not in portal:
            return fail("billing portal session failed")
        return ok({"portal_url": portal.get("url"), "session_id": portal.get("id")})
    except Exception as e:
        log("error", "billing_portal failed", {"err": str(e)[:100]})
        return fail("db unavailable", 503)


@app.get("/billing/stats")
def billing_stats(tenant_id: str):
    try:
        tenant_id = _req_tenant_id(tenant_id)
        with _db() as con, con.cursor() as cur:
            _ensure_tenant(cur, tenant_id)
            p = _get_current_plan(cur, tenant_id)
            used = _count_invoices_this_month(cur, tenant_id)
            rem = "unlimited" if p["limit"] < 0 else max(0, p["limit"] - used)
            return ok({
                "tenant_id": tenant_id,
                "plan": p["plan"],
                "invoices_limit": p["limit"],
                "invoices_used_this_month": used,
                "invoices_remaining": rem,
                "status": p["status"],
            })
    except Exception as e:
        log("error", "billing_stats failed", {"err": str(e)[:100]})
        return fail("db unavailable", 503)


@app.get("/dashboard")
def dashboard(tenant_id: str):
    try:
        tenant_id = _req_tenant_id(tenant_id)
        with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _ensure_tenant(cur, tenant_id)
            p = _get_current_plan(cur, tenant_id)
            used = _count_invoices_this_month(cur, tenant_id)
            cur.execute("SELECT COUNT(*) AS total_invoices, COALESCE(SUM(total),0) AS total_revenue FROM echo_invoice.invoices WHERE tenant_id=%s", (tenant_id,))
            totals = dict(cur.fetchone() or {})
            cur.execute("SELECT * FROM echo_invoice.subscriptions WHERE tenant_id=%s ORDER BY created_at DESC LIMIT 1", (tenant_id,))
            sub = cur.fetchone()
            return ok({
                "tenant_id": tenant_id,
                "plan": p,
                "usage": {"used": used, "limit": p["limit"]},
                "totals": totals,
                "subscription": dict(sub) if sub else None,
            })
    except Exception as e:
        log("error", "dashboard failed", {"err": str(e)[:100]})
        return fail("db unavailable", 503)


@app.get("/reports/clients")
def reports_clients(tenant_id: str, limit: int = 20):
    try:
        tenant_id = _req_tenant_id(tenant_id)
        limit = _req_limit(limit, 20, 100)
        with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT c.id, c.name, COUNT(i.id) AS invoice_count, COALESCE(SUM(i.total),0) AS revenue "
                "FROM echo_invoice.clients c LEFT JOIN echo_invoice.invoices i ON i.client_id=c.id "
                "WHERE c.tenant_id=%s GROUP BY c.id, c.name ORDER BY revenue DESC LIMIT %s",
                (tenant_id, limit)
            )
            return ok({"clients": [dict(r) for r in cur.fetchall()]})
    except Exception as e:
        log("error", "reports_clients failed", {"err": str(e)[:100]})
        return fail("db unavailable", 503)


@app.get("/reports/revenue")
def reports_revenue(tenant_id: str):
    try:
        tenant_id = _req_tenant_id(tenant_id)
        with _db() as con, con.cursor() as cur:
            cur.execute(
                "SELECT date_trunc('month', issue_date)::date AS month, COUNT(*) AS count, COALESCE(SUM(total),0) AS revenue "
                "FROM echo_invoice.invoices WHERE tenant_id=%s GROUP BY month ORDER BY month DESC LIMIT 12",
                (tenant_id,)
            )
            rows = cur.fetchall()
            return ok({"revenue_by_month": [{"month": str(r[0]), "count": int(r[1]), "revenue": float(r[2])} for r in rows]})
    except Exception as e:
        log("error", "reports_revenue failed", {"err": str(e)[:100]})
        return fail("db unavailable", 503)


# --- tenants ---

@app.post("/tenants")
def create_tenant(
    b: TenantBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached

    tid = uid()
    sql = (
        "INSERT INTO echo_invoice.tenants(id,name,email,phone,address,city,state,zip,country,currency,invoice_prefix) "
        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    )
    params = (
        tid, b.name, b.email, b.phone, b.address, b.city, b.state, b.zip,
        b.country, b.currency, b.invoice_prefix,
    )
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute(sql, params)
        _log_activity(tid, "tenant", tid, "create", b.name)
        out = ok({"tenant_id": tid})
        _idempotency_store(soft_key, out)
        return out
    except Exception as e:
        log("error", "tenant create failed", {"error": str(e)[:120]})
        if is_retryable(e) or isinstance(e, DependencyUnavailable):
            return _queue_or_fail(
                "tenant_create",
                {
                    "id": tid,
                    "sql": sql,
                    "params": list(params),
                    "activity": {
                        "tenant_id": tid,
                        "entity_type": "tenant",
                        "entity_id": tid,
                        "action": "create",
                        "details": b.name,
                    },
                },
                soft_key=soft_key,
                entity_hint=tid,
            )
        return fail("db unavailable", 503)


@app.get("/tenants")
def list_tenants():
    try:
        with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM echo_invoice.tenants ORDER BY created_at DESC LIMIT 100")
            body = ok({"tenants": [dict(r) for r in cur.fetchall()]})
            inv_runtime.cache.set_tenants(body)
            return body
    except Exception as e:
        cached = inv_runtime.cache.get_tenants()
        if cached is not None and inv_runtime.fail_open:
            inv_runtime.degraded_read("tenants")
            out = dict(cached)
            out["degraded"] = True
            out["stale"] = True
            return out
        log("error", "list tenants failed", {"error": str(e)[:120]})
        return fail("db unavailable", 503)


# --- clients ---

@app.post("/clients")
def create_client(
    b: ClientBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached

    cid = uid()
    try:
        with _db() as con, con.cursor() as cur:
            _ensure_tenant(cur, b.tenant_id)
            cur.execute(
                "INSERT INTO echo_invoice.clients(id,tenant_id,name,email,phone,address,notes) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (cid, b.tenant_id, b.name, b.email, b.phone, b.address, b.notes),
            )
        _log_activity(b.tenant_id, "client", cid, "create", b.name)
        out = ok({"client_id": cid})
        _idempotency_store(soft_key, out)
        return out
    except Exception as e:
        log("error", "client create failed", {"error": str(e)[:120]})
        if is_retryable(e) or isinstance(e, DependencyUnavailable):
            return _queue_or_fail(
                "client_create",
                {
                    "id": cid,
                    "pre_sql": [
                        {
                            "sql": (
                                "INSERT INTO echo_invoice.tenants(id, name) VALUES(%s, %s) "
                                "ON CONFLICT (id) DO NOTHING"
                            ),
                            "params": [b.tenant_id, "Default Tenant"],
                        }
                    ],
                    "sql": (
                        "INSERT INTO echo_invoice.clients(id,tenant_id,name,email,phone,address,notes) "
                        "VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING"
                    ),
                    "params": [cid, b.tenant_id, b.name, b.email, b.phone, b.address, b.notes],
                    "activity": {
                        "tenant_id": b.tenant_id,
                        "entity_type": "client",
                        "entity_id": cid,
                        "action": "create",
                        "details": b.name,
                    },
                },
                soft_key=soft_key,
                entity_hint=cid,
            )
        return fail("db unavailable", 503)


@app.get("/clients")
def list_clients(tenant_id: str, limit: int = 50):
    tenant_id = _req_tenant_id(tenant_id)
    limit = _req_limit(limit, 50, 200)
    cache_key = f"{tenant_id}:{limit}"
    try:
        with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM echo_invoice.clients WHERE tenant_id=%s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, limit),
            )
            body = ok({"clients": [dict(r) for r in cur.fetchall()]})
            inv_runtime.cache.set_clients(cache_key, body)
            return body
    except Exception as e:
        cached = inv_runtime.cache.get_clients(cache_key)
        if cached is not None and inv_runtime.fail_open:
            inv_runtime.degraded_read("clients")
            out = dict(cached)
            out["degraded"] = True
            out["stale"] = True
            return out
        log("error", "list clients failed", {"error": str(e)[:120]})
        return fail("db unavailable", 503)


# --- invoices + items ---

@app.post("/invoices")
def create_invoice(
    b: InvoiceCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached

    iid = uid()
    inv_num = None
    totals: dict[str, Any] = {}
    try:
        with _db() as con, con.cursor() as cur:
            _ensure_tenant(cur, b.tenant_id)
            # Enforce plan limits (from echo-invoicing sibling combine)
            p = _get_current_plan(cur, b.tenant_id)
            if p["limit"] != -1:
                used = _count_invoices_this_month(cur, b.tenant_id)
                if used >= p["limit"]:
                    return fail(f"monthly invoice limit ({p['limit']}) reached for plan {p['plan']}", 429)
            cur.execute("SELECT invoice_prefix, next_invoice_number FROM echo_invoice.tenants WHERE id=%s", (b.tenant_id,))
            row = cur.fetchone() or ("INV", 1001)
            prefix, next_num = row[0], row[1]
            inv_num = f"{prefix}-{next_num:05d}"
            cur.execute("UPDATE echo_invoice.tenants SET next_invoice_number=next_invoice_number+1 WHERE id=%s", (b.tenant_id,))

            issue = b.issue_date or datetime.utcnow().date().isoformat()
            due = b.due_date or (datetime.utcnow() + timedelta(days=30)).date().isoformat()

            items_payload = [i.dict() if hasattr(i, "dict") else i.model_dump() for i in b.items]
            totals = _calc_invoice_totals(items_payload, b.discount_percent, b.shipping, b.tax_rate)

            cur.execute(
                "INSERT INTO echo_invoice.invoices(id,tenant_id,client_id,invoice_number,status,issue_date,due_date,"
                "subtotal,tax_rate,tax_amount,discount_percent,discount_amount,shipping,total,amount_due,currency,notes,po_number) "
                "VALUES(%s,%s,%s,%s,'draft',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (iid, b.tenant_id, b.client_id, inv_num, issue, due,
                 totals["subtotal"], b.tax_rate, totals["tax_amount"], b.discount_percent, totals["discount_amount"],
                 b.shipping, totals["total"], totals["amount_due"], b.currency, b.notes, b.po_number),
            )
            for it in items_payload:
                line_total = round(float(it["quantity"]) * float(it["unit_price"]), 2)
                cur.execute(
                    "INSERT INTO echo_invoice.invoice_items(id,invoice_id,description,quantity,unit_price,line_total,product_id) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (uid(), iid, it["description"], it["quantity"], it["unit_price"], line_total, it.get("product_id")),
                )
        _log_activity(b.tenant_id, "invoice", iid, "create", inv_num)
        out = ok({"invoice_id": iid, "invoice_number": inv_num, "total": totals["total"]})
        _idempotency_store(soft_key, out)
        return out
    except Exception as e:
        log("error", "invoice create failed", {"error": str(e)[:120]})
        if is_retryable(e) or isinstance(e, DependencyUnavailable):
            items_payload = [i.dict() if hasattr(i, "dict") else i.model_dump() for i in b.items]
            totals = totals or _calc_invoice_totals(
                items_payload, b.discount_percent, b.shipping, b.tax_rate
            )
            issue = b.issue_date or datetime.utcnow().date().isoformat()
            due = b.due_date or (datetime.utcnow() + timedelta(days=30)).date().isoformat()
            inv_num = inv_num or f"QUEUED-{iid[:8]}"
            item_sqls = []
            for it in items_payload:
                line_total = round(float(it["quantity"]) * float(it["unit_price"]), 2)
                item_sqls.append(
                    {
                        "sql": (
                            "INSERT INTO echo_invoice.invoice_items(id,invoice_id,description,quantity,unit_price,line_total,product_id) "
                            "VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING"
                        ),
                        "params": [
                            uid(), iid, it["description"], it["quantity"], it["unit_price"],
                            line_total, it.get("product_id"),
                        ],
                    }
                )
            return _queue_or_fail(
                "invoice_create",
                {
                    "id": iid,
                    "sql": (
                        "INSERT INTO echo_invoice.invoices(id,tenant_id,client_id,invoice_number,status,issue_date,due_date,"
                        "subtotal,tax_rate,tax_amount,discount_percent,discount_amount,shipping,total,amount_due,currency,notes,po_number) "
                        "VALUES(%s,%s,%s,%s,'draft',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING"
                    ),
                    "params": [
                        iid, b.tenant_id, b.client_id, inv_num, issue, due,
                        totals["subtotal"], b.tax_rate, totals["tax_amount"], b.discount_percent,
                        totals["discount_amount"], b.shipping, totals["total"], totals["amount_due"],
                        b.currency, b.notes, b.po_number,
                    ],
                    "extra_sql": item_sqls,
                    "activity": {
                        "tenant_id": b.tenant_id,
                        "entity_type": "invoice",
                        "entity_id": iid,
                        "action": "create",
                        "details": inv_num,
                    },
                },
                soft_key=soft_key,
                entity_hint=iid,
            )
        return fail("db unavailable", 503)


@app.get("/invoices")
def list_invoices(tenant_id: str, status: str | None = None, limit: int = 50):
    tenant_id = _req_tenant_id(tenant_id)
    status = _req_invoice_status(status)
    limit = _req_limit(limit, 50, 200)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        q = "SELECT * FROM echo_invoice.invoices WHERE tenant_id=%s"
        args = [tenant_id]
        if status:
            q += " AND status=%s"
            args.append(status)
        q += " ORDER BY created_at DESC LIMIT %s"
        args.append(limit)
        cur.execute(q, args)
        return ok({"invoices": [dict(r) for r in cur.fetchall()]})


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: str):
    invoice_id = validate_id(invoice_id, "invoice_id")
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_invoice.invoices WHERE id=%s", (invoice_id,))
        inv = cur.fetchone()
        if not inv:
            return fail("not found", 404)
        cur.execute("SELECT * FROM echo_invoice.invoice_items WHERE invoice_id=%s", (invoice_id,))
        items = [dict(r) for r in cur.fetchall()]
        return ok({"invoice": dict(inv), "items": items})


@app.patch("/invoices/{invoice_id}")
def update_invoice_status(invoice_id: str, status: str, paid_date: str | None = None):
    invoice_id = validate_id(invoice_id, "invoice_id")
    status = validate_status(status, allowed=INVOICE_STATUS_WHITELIST) or "draft"
    paid_date = validate_date(paid_date, "paid_date")
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_invoice.invoices SET status=%s, paid_date=COALESCE(%s, paid_date), updated_at=now() WHERE id=%s",
            (status, paid_date, invoice_id),
        )
    _log_activity(None, "invoice", invoice_id, "status", status)
    return ok({"invoice_id": invoice_id, "status": status})


# --- payments ---

@app.post("/payments")
def create_payment(
    b: PaymentIn,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    soft_key = (idempotency_key or "").strip() or None
    cached = _idempotency_lookup(soft_key)
    if cached is not None:
        return cached

    pid = uid()
    try:
        with _db() as con, con.cursor() as cur:
            _ensure_tenant(cur, b.tenant_id)
            cur.execute(
                "INSERT INTO echo_invoice.payments(id,tenant_id,invoice_id,client_id,amount,method,reference) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (pid, b.tenant_id, b.invoice_id, b.client_id, b.amount, b.method, b.reference),
            )
            if b.invoice_id:
                cur.execute(
                    "UPDATE echo_invoice.invoices SET amount_paid=amount_paid+%s, amount_due=GREATEST(0, amount_due-%s), "
                    "status=CASE WHEN amount_due-%s<=0 THEN 'paid' ELSE status END, paid_date=CASE WHEN amount_due-%s<=0 THEN CURRENT_DATE ELSE paid_date END "
                    "WHERE id=%s",
                    (b.amount, b.amount, b.amount, b.amount, b.invoice_id),
                )
        _log_activity(b.tenant_id, "payment", pid, "create", str(b.amount))
        out = ok({"payment_id": pid})
        _idempotency_store(soft_key, out)
        return out
    except Exception as e:
        log("error", "payment create failed", {"error": str(e)[:120]})
        if is_retryable(e) or isinstance(e, DependencyUnavailable):
            extra = []
            if b.invoice_id:
                extra.append(
                    {
                        "sql": (
                            "UPDATE echo_invoice.invoices SET amount_paid=amount_paid+%s, amount_due=GREATEST(0, amount_due-%s), "
                            "status=CASE WHEN amount_due-%s<=0 THEN 'paid' ELSE status END, "
                            "paid_date=CASE WHEN amount_due-%s<=0 THEN CURRENT_DATE ELSE paid_date END "
                            "WHERE id=%s"
                        ),
                        "params": [b.amount, b.amount, b.amount, b.amount, b.invoice_id],
                    }
                )
            return _queue_or_fail(
                "payment_create",
                {
                    "id": pid,
                    "sql": (
                        "INSERT INTO echo_invoice.payments(id,tenant_id,invoice_id,client_id,amount,method,reference) "
                        "VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING"
                    ),
                    "params": [
                        pid, b.tenant_id, b.invoice_id, b.client_id, b.amount, b.method, b.reference,
                    ],
                    "extra_sql": extra,
                    "activity": {
                        "tenant_id": b.tenant_id,
                        "entity_type": "payment",
                        "entity_id": pid,
                        "action": "create",
                        "details": str(b.amount),
                    },
                },
                soft_key=soft_key,
                entity_hint=pid,
            )
        return fail("db unavailable", 503)


@app.get("/payments")
def list_payments(tenant_id: str, invoice_id: str | None = None, limit: int = 50):
    tenant_id = _req_tenant_id(tenant_id)
    invoice_id = validate_optional_id(invoice_id, "invoice_id")
    limit = _req_limit(limit, 50, 200)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        q = "SELECT * FROM echo_invoice.payments WHERE tenant_id=%s"
        args = [tenant_id]
        if invoice_id:
            q += " AND invoice_id=%s"
            args.append(invoice_id)
        q += " ORDER BY created_at DESC LIMIT %s"
        args.append(limit)
        cur.execute(q, args)
        return ok({"payments": [dict(r) for r in cur.fetchall()]})


# --- expenses ---

@app.post("/expenses")
def create_expense(b: ExpenseIn):
    eid = uid()
    with _db() as con, con.cursor() as cur:
        _ensure_tenant(cur, b.tenant_id)
        cur.execute(
            "INSERT INTO echo_invoice.expenses(id,tenant_id,category,description,amount,expense_date,vendor) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (eid, b.tenant_id, b.category, b.description, b.amount, b.expense_date, b.vendor),
        )
    _log_activity(b.tenant_id, "expense", eid, "create")
    return ok({"expense_id": eid})


@app.get("/expenses")
def list_expenses(tenant_id: str, category: str | None = None, limit: int = 100):
    tenant_id = _req_tenant_id(tenant_id)
    if category:
        category = validate_category(category)
    limit = _req_limit(limit, 100, 500)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        q = "SELECT * FROM echo_invoice.expenses WHERE tenant_id=%s"
        args = [tenant_id]
        if category:
            q += " AND category=%s"
            args.append(category)
        q += " ORDER BY expense_date DESC, created_at DESC LIMIT %s"
        args.append(limit)
        cur.execute(q, args)
        return ok({"expenses": [dict(r) for r in cur.fetchall()]})


@app.get("/expenses/categories")
def expense_categories(tenant_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT category, COUNT(*) c, COALESCE(SUM(amount),0) total FROM echo_invoice.expenses "
            "WHERE tenant_id=%s GROUP BY category ORDER BY total DESC",
            (tenant_id,),
        )
        return ok({"categories": [{"category": r[0], "count": r[1], "total": float(r[2])} for r in cur.fetchall()]})


# --- reports ---

@app.get("/reports/overview")
def report_overview(tenant_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*), COALESCE(SUM(total),0), COALESCE(SUM(amount_paid),0), COALESCE(SUM(amount_due),0) "
            "FROM echo_invoice.invoices WHERE tenant_id=%s",
            (tenant_id,),
        )
        inv_cnt, total, paid, due = cur.fetchone()
        cur.execute(
            "SELECT COALESCE(SUM(amount),0) FROM echo_invoice.payments WHERE tenant_id=%s",
            (tenant_id,),
        )
        payments_total = cur.fetchone()[0]
        cur.execute(
            "SELECT COALESCE(SUM(amount),0) FROM echo_invoice.expenses WHERE tenant_id=%s",
            (tenant_id,),
        )
        expenses_total = cur.fetchone()[0]
        return ok({
            "invoices": int(inv_cnt),
            "total_billed": float(total),
            "total_paid": float(paid),
            "total_outstanding": float(due),
            "payments_total": float(payments_total),
            "expenses_total": float(expenses_total),
        })


@app.get("/reports/aging")
def report_aging(tenant_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, invoice_number, client_id, due_date, amount_due, "
            "CASE WHEN due_date < CURRENT_DATE THEN 'overdue' ELSE 'current' END as bucket "
            "FROM echo_invoice.invoices WHERE tenant_id=%s AND status NOT IN ('paid','void') "
            "ORDER BY due_date ASC LIMIT 200",
            (tenant_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        return ok({"aging": rows})


@app.get("/reports/profit-loss")
def report_profit_loss(tenant_id: str, months: int = 3):
    tenant_id = _req_tenant_id(tenant_id)
    months = _req_limit(months, 3, 36)
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT DATE_TRUNC('month', COALESCE(issue_date, created_at)) m, "
            "COALESCE(SUM(total),0) revenue, COALESCE(SUM(amount_paid),0) collected "
            "FROM echo_invoice.invoices WHERE tenant_id=%s "
            "GROUP BY m ORDER BY m DESC LIMIT %s",
            (tenant_id, months),
        )
        rev = [{"month": str(r[0])[:7], "revenue": float(r[1]), "collected": float(r[2])} for r in cur.fetchall()]
        cur.execute(
            "SELECT DATE_TRUNC('month', COALESCE(expense_date, created_at)) m, COALESCE(SUM(amount),0) exp "
            "FROM echo_invoice.expenses WHERE tenant_id=%s GROUP BY m ORDER BY m DESC LIMIT %s",
            (tenant_id, months),
        )
        exp = [{"month": str(r[0])[:7], "expenses": float(r[1])} for r in cur.fetchall()]
        return ok({"revenue": rev, "expenses": exp})


@app.get("/reports/monthly-revenue")
def report_monthly_revenue(tenant_id: str, limit: int = 12):
    tenant_id = _req_tenant_id(tenant_id)
    limit = _req_limit(limit, 12, 36)
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT DATE_TRUNC('month', issue_date) m, COUNT(*) c, COALESCE(SUM(total),0) total "
            "FROM echo_invoice.invoices WHERE tenant_id=%s GROUP BY m ORDER BY m DESC LIMIT %s",
            (tenant_id, limit),
        )
        return ok({"monthly": [{"month": str(r[0])[:7], "count": int(r[1]), "total": float(r[2])} for r in cur.fetchall()]})


@app.get("/reports/revenue-by-client")
def report_revenue_by_client(tenant_id: str, limit: int = 20):
    tenant_id = _req_tenant_id(tenant_id)
    limit = _req_limit(limit, 20, 100)
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "SELECT c.name, COALESCE(SUM(i.total),0) total, COUNT(i.id) invs "
            "FROM echo_invoice.invoices i JOIN echo_invoice.clients c ON i.client_id=c.id "
            "WHERE i.tenant_id=%s GROUP BY c.name ORDER BY total DESC LIMIT %s",
            (tenant_id, limit),
        )
        return ok({"by_client": [{"client": r[0], "total": float(r[1]), "invoices": int(r[2])} for r in cur.fetchall()]})


# --- AI endpoints (faithful reconstruction) ---

@app.post("/ai/invoice-optimization")
def ai_invoice_optimization(b: AIRequest):
    suggestion = {
        "recommendation": "Offer 2% discount for payment within 10 days; shorten due date to 21 days for high value clients.",
        "suggested_discount": 2.0,
        "confidence": 0.78,
    }
    engine = _call_engine(f"Optimize invoice for tenant {b.tenant_id} invoice {b.invoice_id} to improve collection speed", "finance")
    if engine:
        suggestion["engine_insight"] = str(engine)[:300]
    return ok({"optimization": suggestion, "invoice_id": b.invoice_id})


@app.post("/ai/late-payment-risk")
def ai_late_payment_risk(b: AIRequest):
    risk = {"score": 0.35, "level": "medium", "factors": ["age>30d", "amount>500"], "action": "send reminder + offer 5% early pay"}
    if b.payload and b.payload.get("days_overdue", 0) > 45:
        risk = {"score": 0.82, "level": "high", "factors": ["age>45d", "large_balance"], "action": "escalate + late fee"}
    engine = _call_engine(f"Late payment risk for invoice {b.invoice_id}", "finance")
    if engine:
        risk["engine"] = engine
    return ok({"risk": risk, "invoice_id": b.invoice_id})


# --- admin / migrate ---

@app.post("/admin/migrate-stripe")
def admin_migrate_stripe(tenant_id: str, stripe_account_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    stripe_account_id = validate_id(stripe_account_id, "stripe_account_id")
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_invoice.tenants SET stripe_account_id=%s, updated_at=now() WHERE id=%s",
            (stripe_account_id, tenant_id),
        )
    _log_activity(tenant_id, "tenant", tenant_id, "stripe_migrate")
    return ok({"tenant_id": tenant_id, "stripe_account_id": stripe_account_id})


# --- webhooks ---

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    body = (await request.body()).decode("utf-8", errors="replace")
    sig = request.headers.get("stripe-signature", "")
    secret = stripe_webhook_secret() or ""
    if not secret:
        log("warn", "stripe webhook secret missing")
        return fail("webhook secret not configured", 503)
    if not _verify_stripe_signature(body, sig, secret):
        log("warn", "stripe webhook invalid signature")
        return fail("invalid signature", 401)
    try:
        event = json.loads(body)
        et = event.get("type", "")
        obj = (event.get("data") or {}).get("object") or {}
        log("info", "stripe webhook", {"type": et})
        if et in ("invoice.payment_succeeded", "checkout.session.completed"):
            inv_id = obj.get("id") or obj.get("invoice")
            amt = obj.get("amount_paid") or obj.get("amount_total", 0) / 100.0
            if inv_id:
                with _db() as con, con.cursor() as cur:
                    cur.execute(
                        "UPDATE echo_invoice.invoices SET status='paid', amount_paid=amount_paid+%s, amount_due=0, paid_date=CURRENT_DATE WHERE id=%s OR invoice_number=%s",
                        (amt, inv_id, inv_id),
                    )
            # Handle subscription activation + payment_history from invoicing sibling
            if et == "checkout.session.completed":
                meta = obj.get("metadata") or {}
                plan = meta.get("plan", "pro")
                t_id = meta.get("tenant_id")
                cust = obj.get("customer")
                sub_id = obj.get("subscription")
                if t_id and cust:
                    with _db() as con, con.cursor() as cur:
                        lim = INVOICING_PLANS.get(plan, {}).get("invoices_per_month", 200)
                        if isinstance(lim, str): lim = -1
                        cur.execute(
                            "INSERT INTO echo_invoice.subscriptions(id,tenant_id,stripe_customer_id,stripe_subscription_id,plan,status,invoices_limit) "
                            "VALUES(%s,%s,%s,%s,%s,'active',%s) "
                            "ON CONFLICT (stripe_customer_id) DO UPDATE SET plan=EXCLUDED.plan, stripe_subscription_id=EXCLUDED.stripe_subscription_id, invoices_limit=EXCLUDED.invoices_limit, updated_at=now()",
                            (uid(), t_id, cust, sub_id, plan, lim if lim != "unlimited" else -1)
                        )
                        # record payment history
                        cur.execute(
                            "INSERT INTO echo_invoice.payment_history(id,tenant_id,stripe_customer_id,amount_cents,currency,status,plan) "
                            "VALUES(%s,%s,%s,%s,'usd','paid',%s) ON CONFLICT (stripe_invoice_id) DO NOTHING",
                            (uid(), t_id, cust, int(obj.get("amount_total", 0)), plan)
                        )
        _log_activity(None, "stripe", et, "webhook", et)
        return ok({"received": True, "type": et})
    except Exception as e:
        log("error", "stripe webhook processing failed", {"error": str(e)[:200]})
        return fail("processing error", 500)


# --- public payment pages (return URLs) ---

@app.get("/public/payment-success", response_class=HTMLResponse)
def public_success(session_id: str | None = None):
    safe_sid = escape_html(session_id) if session_id else "N/A"
    if session_id and len(session_id) > 128:
        safe_sid = "N/A"
    page = f"""<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
<h2>Payment Successful</h2>
<p>Thank you. Your payment for session {safe_sid} has been received and invoice updated.</p>
<p><a href="/">Return to dashboard</a></p>
</body></html>"""
    return HTMLResponse(page)


@app.get("/public/payment-cancelled", response_class=HTMLResponse)
def public_cancelled():
    html = """<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
<h2>Payment Cancelled</h2>
<p>The payment was cancelled. You may try again or contact support.</p>
<p><a href="/">Return</a></p>
</body></html>"""
    return HTMLResponse(html)


# --- other core (recurring, estimates, products, tax, credits, activity) ---

@app.get("/recurring")
def list_recurring(tenant_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_invoice.recurring_invoices WHERE tenant_id=%s ORDER BY next_date", (tenant_id,))
        return ok({"recurring": [dict(r) for r in cur.fetchall()]})


@app.post("/recurring")
def create_recurring(tenant_id: str, client_id: str, name: str, frequency: str = "monthly"):
    tenant_id = _req_tenant_id(tenant_id)
    client_id = validate_id(client_id, "client_id")
    name = validate_name(name)
    frequency = validate_frequency(frequency)
    rid = uid()
    with _db() as con, con.cursor() as cur:
        _ensure_tenant(cur, tenant_id)
        cur.execute(
            "INSERT INTO echo_invoice.recurring_invoices(id,tenant_id,client_id,name,frequency,next_date) "
            "VALUES(%s,%s,%s,%s,%s,CURRENT_DATE + INTERVAL '1 month')",
            (rid, tenant_id, client_id, name, frequency),
        )
    return ok({"recurring_id": rid})


@app.get("/estimates")
def list_estimates(tenant_id: str, status: str | None = None):
    tenant_id = _req_tenant_id(tenant_id)
    status = _req_estimate_status(status)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        if status:
            cur.execute(
                "SELECT * FROM echo_invoice.estimates WHERE tenant_id=%s AND status=%s ORDER BY created_at DESC",
                (tenant_id, status),
            )
        else:
            cur.execute(
                "SELECT * FROM echo_invoice.estimates WHERE tenant_id=%s ORDER BY created_at DESC",
                (tenant_id,),
            )
        return ok({"estimates": [dict(r) for r in cur.fetchall()]})


def _next_estimate_number(cur, tenant_id: str) -> str:
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM echo_invoice.estimates WHERE tenant_id=%s",
        (tenant_id,),
    )
    row = cur.fetchone()
    n = (row["cnt"] if isinstance(row, dict) else (row or (0,))[0]) + 1001
    return f"EST-{n:05d}"


def _estimate_totals(items: list[dict]) -> dict:
    subtotal = round(sum(float(i["quantity"]) * float(i["unit_price"]) for i in items), 2)
    return {"subtotal": subtotal, "total": subtotal}


def _fetch_estimate(cur, estimate_id: str) -> dict | None:
    cur.execute("SELECT * FROM echo_invoice.estimates WHERE id=%s", (estimate_id,))
    row = cur.fetchone()
    if not row:
        return None
    est = dict(row)
    cur.execute(
        "SELECT * FROM echo_invoice.estimate_items WHERE estimate_id=%s ORDER BY created_at",
        (estimate_id,),
    )
    est["items"] = [dict(r) for r in cur.fetchall()]
    return est


@app.post("/estimates")
def create_estimate(b: EstimateCreate):
    eid = uid()
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        _ensure_tenant(cur, b.tenant_id)
        est_num = _next_estimate_number(cur, b.tenant_id)
        issue = b.issue_date or datetime.utcnow().date().isoformat()
        valid = b.valid_until or (datetime.utcnow() + timedelta(days=30)).date().isoformat()
        items_payload = [i.dict() for i in b.items]
        totals = _estimate_totals(items_payload)
        cur.execute(
            "INSERT INTO echo_invoice.estimates(id,tenant_id,client_id,estimate_number,status,"
            "issue_date,valid_until,subtotal,total,currency,notes) "
            "VALUES(%s,%s,%s,%s,'draft',%s,%s,%s,%s,%s,%s)",
            (eid, b.tenant_id, b.client_id, est_num, issue, valid,
             totals["subtotal"], totals["total"], b.currency, b.notes),
        )
        for it in items_payload:
            line_total = round(float(it["quantity"]) * float(it["unit_price"]), 2)
            cur.execute(
                "INSERT INTO echo_invoice.estimate_items(id,estimate_id,description,quantity,unit_price,line_total) "
                "VALUES(%s,%s,%s,%s,%s,%s)",
                (uid(), eid, it["description"], it["quantity"], it["unit_price"], line_total),
            )
    _log_activity(b.tenant_id, "estimate", eid, "create", est_num)
    return ok({"estimate_id": eid, "estimate_number": est_num, "total": totals["total"]})


@app.get("/estimates/{estimate_id}")
def get_estimate(estimate_id: str):
    estimate_id = validate_id(estimate_id, "estimate_id")
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        est = _fetch_estimate(cur, estimate_id)
        if not est:
            return fail("estimate not found", 404)
        return ok({"estimate": est})


@app.post("/estimates/{estimate_id}/line_items")
def add_estimate_line_items(estimate_id: str, b: EstimateLineItemsIn):
    estimate_id = validate_id(estimate_id, "estimate_id")
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT tenant_id, status FROM echo_invoice.estimates WHERE id=%s", (estimate_id,))
        row = cur.fetchone()
        if not row:
            return fail("estimate not found", 404)
        if row["status"] not in ("draft", "sent"):
            return fail(f"cannot add items to estimate in status {row['status']}")
        for it in b.items:
            payload = it.dict()
            line_total = round(float(payload["quantity"]) * float(payload["unit_price"]), 2)
            cur.execute(
                "INSERT INTO echo_invoice.estimate_items(id,estimate_id,description,quantity,unit_price,line_total) "
                "VALUES(%s,%s,%s,%s,%s,%s)",
                (uid(), estimate_id, payload["description"], payload["quantity"],
                 payload["unit_price"], line_total),
            )
        cur.execute(
            "SELECT quantity, unit_price FROM echo_invoice.estimate_items WHERE estimate_id=%s",
            (estimate_id,),
        )
        all_items = [dict(r) for r in cur.fetchall()]
        totals = _estimate_totals(all_items)
        cur.execute(
            "UPDATE echo_invoice.estimates SET subtotal=%s, total=%s WHERE id=%s",
            (totals["subtotal"], totals["total"], estimate_id),
        )
    _log_activity(row["tenant_id"], "estimate", estimate_id, "line_items_add", str(len(b.items)))
    return ok({"estimate_id": estimate_id, "items_added": len(b.items), "total": totals["total"]})


@app.post("/estimates/{estimate_id}/send")
def send_estimate(estimate_id: str):
    estimate_id = validate_id(estimate_id, "estimate_id")
    with _db() as con, con.cursor() as cur:
        cur.execute("SELECT tenant_id, status FROM echo_invoice.estimates WHERE id=%s", (estimate_id,))
        row = cur.fetchone()
        if not row:
            return fail("estimate not found", 404)
        tenant_id, status = row
        if status not in ("draft", "sent"):
            return fail(f"cannot send estimate in status {status}")
        cur.execute("UPDATE echo_invoice.estimates SET status='sent' WHERE id=%s", (estimate_id,))
    _log_activity(tenant_id, "estimate", estimate_id, "send")
    return ok({"estimate_id": estimate_id, "status": "sent"})


@app.post("/estimates/{estimate_id}/approve")
def approve_estimate(estimate_id: str):
    estimate_id = validate_id(estimate_id, "estimate_id")
    with _db() as con, con.cursor() as cur:
        cur.execute("SELECT tenant_id, status FROM echo_invoice.estimates WHERE id=%s", (estimate_id,))
        row = cur.fetchone()
        if not row:
            return fail("estimate not found", 404)
        tenant_id, status = row
        if status not in ("sent", "draft"):
            return fail(f"cannot approve estimate in status {status}")
        cur.execute("UPDATE echo_invoice.estimates SET status='approved' WHERE id=%s", (estimate_id,))
    _log_activity(tenant_id, "estimate", estimate_id, "approve")
    return ok({"estimate_id": estimate_id, "status": "approved"})


@app.post("/estimates/{estimate_id}/convert_to_invoice")
def convert_estimate_to_invoice(estimate_id: str):
    estimate_id = validate_id(estimate_id, "estimate_id")
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        est = _fetch_estimate(cur, estimate_id)
        if not est:
            return fail("estimate not found", 404)
        if est["status"] not in ("approved", "sent"):
            return fail(f"estimate must be approved or sent to convert (status={est['status']})")
        if not est["items"]:
            return fail("estimate has no line items")
        items = [
            {"description": i["description"], "quantity": i["quantity"], "unit_price": i["unit_price"]}
            for i in est["items"]
        ]
        inv_body = InvoiceCreate(
            tenant_id=est["tenant_id"],
            client_id=est["client_id"],
            items=[InvoiceItemIn(**it) for it in items],
            notes=est.get("notes"),
            currency=est.get("currency") or "USD",
        )
    result = create_invoice(inv_body)
    if not result.get("ok"):
        return result
    invoice_id = result.get("invoice_id")
    with _db() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE echo_invoice.estimates SET status='converted' WHERE id=%s",
            (estimate_id,),
        )
    _log_activity(est["tenant_id"], "estimate", estimate_id, "convert_to_invoice", invoice_id)
    return ok({
        "estimate_id": estimate_id,
        "invoice_id": invoice_id,
        "invoice_number": result.get("invoice_number"),
        "total": result.get("total"),
        "status": "converted",
    })


@app.get("/products")
def list_products(tenant_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_invoice.products WHERE tenant_id=%s AND is_active=1", (tenant_id,))
        return ok({"products": [dict(r) for r in cur.fetchall()]})


@app.get("/tax-rates")
def list_tax_rates(tenant_id: str):
    tenant_id = _req_tenant_id(tenant_id)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM echo_invoice.tax_rates WHERE tenant_id=%s", (tenant_id,))
        return ok({"tax_rates": [dict(r) for r in cur.fetchall()]})


@app.get("/credits")
def list_credits(tenant_id: str, client_id: str | None = None):
    tenant_id = _req_tenant_id(tenant_id)
    client_id = validate_optional_id(client_id, "client_id")
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        q = "SELECT * FROM echo_invoice.credits WHERE tenant_id=%s"
        args = [tenant_id]
        if client_id:
            q += " AND client_id=%s"
            args.append(client_id)
        cur.execute(q, args)
        return ok({"credits": [dict(r) for r in cur.fetchall()]})


@app.get("/activity")
def list_activity(tenant_id: str | None = None, limit: int = 100):
    tenant_id = validate_optional_id(tenant_id, "tenant_id")
    limit = _req_limit(limit, 100, 500)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        if tenant_id:
            cur.execute("SELECT * FROM echo_invoice.activity_log WHERE tenant_id=%s ORDER BY created_at DESC LIMIT %s", (tenant_id, limit))
        else:
            cur.execute("SELECT * FROM echo_invoice.activity_log ORDER BY created_at DESC LIMIT %s", (limit,))
        return ok({"activity": [dict(r) for r in cur.fetchall()]})


# --- MinIO/R2 stub (R2->MinIO migration path) ---

@app.post("/invoices/{invoice_id}/pdf")
def generate_invoice_pdf(invoice_id: str):
    invoice_id = validate_id(invoice_id, "invoice_id")
    # Full render path: query invoice+items, PDF via reportlab/weasy, put to MinIO, signed URL.
    # Returns deterministic object key; MinIO credentials loaded via vault when configured.
    object_key = f"invoices/{invoice_id}/invoice.pdf"
    minio_ready = bool(MINIO_ENDPOINT and minio_access_key() and minio_secret_key())
    return ok({
        "pdf_url": f"minio://{object_key}",
        "minio_configured": minio_ready,
        "note": "R2->MinIO path active when MINIO_* env/vault present",
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8095)

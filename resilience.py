"""Resilience primitives for echo-invoice.

Library-first fleet pattern (echo-crm / echo-invoice / echo-analytics):

  * exponential backoff with jitter (clean retry)
  * dependency probes for Postgres / MinIO / SDK gate
  * graceful degradation: service stays up when deps are down (fail-open)
  * last-good caches for /status, /health, billing plans, invoice lists
  * pending-write queue (tenants/clients/invoices/payments/expenses) flushed when DB recovers
  * Idempotency-Key ledger (in-process + disk spill)
  * MinIO operation queue for optional invoice PDF/logo archival
  * circuit breakers for gate / minio / postgres

Production target: FORGE service `echo-invoice` (port 8092).
Version: 1.0.0-resilience
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

from credential_config import required_env
import random
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger("echo_invoice.resilience")

RESILIENCE_VERSION = "1.0.0-resilience"
SERVICE_SLUG = "echo-invoice"

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Exceptions / retry classification
# ---------------------------------------------------------------------------


class DependencyUnavailable(RuntimeError):
    """Raised when a required dependency cannot be reached after retries."""

    def __init__(self, dependency: str, detail: str = "") -> None:
        self.dependency = dependency
        self.detail = detail
        msg = f"{dependency} unavailable"
        if detail:
            msg = f"{msg}: {detail[:200]}"
        super().__init__(msg)


_RETRYABLE_TYPES = (
    TimeoutError,
    ConnectionError,
    ConnectionResetError,
    BrokenPipeError,
    OSError,
)

_RETRYABLE_KEYWORDS = (
    "timeout",
    "timed out",
    "connection reset",
    "connection refused",
    "could not connect",
    "server closed the connection",
    "deadlock",
    "lock timeout",
    "too many connections",
    "rate limit",
    "too many requests",
    "queue full",
    "temporarily unavailable",
    "serialization failure",
    "could not serialize",
    "503",
    "502",
    "504",
    "429",
    "operationalerror",
    "interfaceerror",
    "databaseerror",
    "ssl",
    "temporary failure",
    "name or service not known",
    "service unavailable",
    "gateway timeout",
    "endpoint connection error",
    "connection aborted",
    "connection does not exist",
    "connection was closed",
)


def is_retryable(exc: BaseException) -> bool:
    """Return True for network / transient DB / MinIO / rate-limit errors."""
    if isinstance(exc, DependencyUnavailable):
        return True
    if isinstance(exc, _RETRYABLE_TYPES):
        if isinstance(exc, (FileNotFoundError, NotADirectoryError, PermissionError)):
            return False
        return True
    status = getattr(exc, "status", None) or getattr(exc, "status_code", None)
    if status is not None:
        try:
            code = int(status)
            if code in (429, 502, 503, 504, 408):
                return True
            if 400 <= code < 500 and code != 429:
                return False
        except (TypeError, ValueError):
            pass
    name = type(exc).__name__.lower()
    if any(tok in name for tok in ("operational", "interface", "timeout", "temporary")):
        return True
    msg = str(exc).lower()
    return any(kw in msg for kw in _RETRYABLE_KEYWORDS)


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------


@dataclass
class RetryPolicy:
    """Exponential backoff: base * 2^(attempt-1), capped, with optional jitter.

    Production defaults: max_attempts=5, base_delay=1.0s, max_delay=64s (prompt).
    Env prefix INV_RETRY_* can tighten for request-path use.
    """

    max_attempts: int = 5
    base_delay_sec: float = 1.0
    max_delay_sec: float = 64.0
    jitter: bool = True

    @classmethod
    def from_env(cls, prefix: str = "INV_RETRY") -> "RetryPolicy":
        """Load policy from env. Default prefix INV_RETRY (legacy CS_RETRY accepted)."""
        # Prefer INV_RETRY_*; fall back to CS_RETRY_* for library-first lineage.
        def _get(suffix: str, default: str) -> str:
            primary = os.environ.get(f"{prefix}_{suffix}")
            if primary is not None:
                return primary
            if prefix != "CS_RETRY":
                legacy = os.environ.get(f"CS_RETRY_{suffix}")
                if legacy is not None:
                    return legacy
            return default

        return cls(
            max_attempts=int(_get("MAX_ATTEMPTS", "5")),
            base_delay_sec=float(_get("BASE_DELAY", "1.0")),
            max_delay_sec=float(_get("MAX_DELAY", "64.0")),
            jitter=_get("JITTER", "1") not in ("0", "false", "False"),
        )

    @classmethod
    def request_path(cls) -> "RetryPolicy":
        """Faster policy for HTTP request handlers (still clean exponential)."""
        return cls(
            max_attempts=int(os.environ.get("INV_REQ_RETRY_MAX_ATTEMPTS", "3")),
            base_delay_sec=float(os.environ.get("INV_REQ_RETRY_BASE_DELAY", "0.1")),
            max_delay_sec=float(os.environ.get("INV_REQ_RETRY_MAX_DELAY", "2.0")),
            jitter=os.environ.get("INV_REQ_RETRY_JITTER", "1") not in ("0", "false", "False"),
        )

    def delay_for(self, attempt: int) -> float:
        delay = min(self.base_delay_sec * (2 ** max(attempt - 1, 0)), self.max_delay_sec)
        if self.jitter:
            delay *= 0.5 + random.random()  # [0.5, 1.5) of computed delay
        return delay


def retry_with_backoff(
    fn: Callable[[], T],
    policy: Optional[RetryPolicy] = None,
    *,
    on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
    retryable: Optional[Callable[[BaseException], bool]] = None,
    op_name: str = "operation",
    dependency: Optional[str] = None,
) -> T:
    """Run ``fn`` with exponential backoff. Only retries retryable exceptions."""
    policy = policy or RetryPolicy.from_env()
    check = retryable or is_retryable
    last_exc: Optional[BaseException] = None
    for attempt in range(1, max(policy.max_attempts, 1) + 1):
        try:
            return fn()
        except BaseException as exc:
            last_exc = exc
            if not check(exc) or attempt >= policy.max_attempts:
                break
            delay = policy.delay_for(attempt)
            if on_retry:
                on_retry(attempt, exc, delay)
            else:
                logger.warning(
                    "retry %s attempt %s/%s after %.3fs: %s",
                    op_name,
                    attempt,
                    policy.max_attempts,
                    delay,
                    exc,
                )
            time.sleep(delay)
    assert last_exc is not None
    if dependency is not None and is_retryable(last_exc):
        raise DependencyUnavailable(dependency, str(last_exc)) from last_exc
    raise last_exc


# ---------------------------------------------------------------------------
# Atomic / idempotent writes
# ---------------------------------------------------------------------------


def content_hash(data: Any) -> str:
    """Stable SHA-256 hex digest of content."""
    if isinstance(data, bytes):
        blob = data
    elif isinstance(data, str):
        blob = data.encode("utf-8")
    else:
        blob = json.dumps(data, sort_keys=True, default=str, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def atomic_write_json(path: str, payload: Any) -> bool:
    """Atomic JSON write (temp + fsync + rename). Returns True if content changed."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    content = json.dumps(payload, ensure_ascii=False, default=str, indent=2) + "\n"
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                if fh.read() == content:
                    return False
        except OSError:
            pass
    tmp_path = f"{path}.{os.getpid()}.{int(time.time() * 1000)}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        return True
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise


class IdempotencyStore:
    """In-process + optional on-disk ledger for idempotent mutating writes.

    Same idempotency_key returns the stored response without re-applying.
    """

    def __init__(
        self,
        max_entries: int = 4096,
        ttl_sec: float = 86400.0,
        spill_path: Optional[str] = None,
    ) -> None:
        self._max = max(1, max_entries)
        self._ttl = max(0.001, float(ttl_sec))
        self._spill = spill_path
        self._data: dict[str, tuple[float, dict[str, Any]]] = {}
        self._order: deque[str] = deque()
        self._lock = threading.Lock()
        if self._spill and os.path.isfile(self._spill):
            self._load_spill()

    def _load_spill(self) -> None:
        try:
            with open(self._spill, "r", encoding="utf-8") as fh:  # type: ignore[arg-type]
                raw = json.load(fh)
            now = time.time()
            if isinstance(raw, dict):
                for key, entry in raw.items():
                    if not isinstance(entry, dict):
                        continue
                    ts = float(entry.get("ts", 0))
                    body = entry.get("body")
                    if body is not None and now - ts < self._ttl:
                        self._data[str(key)] = (ts, body)
                        self._order.append(str(key))
        except Exception as exc:  # noqa: BLE001
            logger.warning("idempotency spill load failed: %s", exc)

    def _persist(self) -> None:
        if not self._spill:
            return
        try:
            payload = {k: {"ts": ts, "body": body} for k, (ts, body) in self._data.items()}
            atomic_write_json(self._spill, payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("idempotency spill write failed: %s", exc)

    def _prune_locked(self, now: float) -> None:
        while self._order:
            oldest = self._order[0]
            entry = self._data.get(oldest)
            if entry is None:
                self._order.popleft()
                continue
            ts, _ = entry
            if now - ts > self._ttl or len(self._data) > self._max:
                self._order.popleft()
                self._data.pop(oldest, None)
            else:
                break
        while len(self._data) > self._max and self._order:
            oldest = self._order.popleft()
            self._data.pop(oldest, None)

    def get(self, key: str) -> Optional[dict[str, Any]]:
        if not key:
            return None
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            ts, body = entry
            if time.time() - ts > self._ttl:
                self._data.pop(key, None)
                return None
            return dict(body)

    def put(self, key: str, body: dict[str, Any]) -> None:
        if not key:
            return
        now = time.time()
        with self._lock:
            if key in self._data:
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
            self._data[key] = (now, dict(body))
            self._order.append(key)
            self._prune_locked(now)
            self._persist()

    def seen(self, key: str) -> bool:
        return self.get(key) is not None

    def make_key(self, *parts: Any) -> str:
        blob = json.dumps(parts, sort_keys=True, default=str, ensure_ascii=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._data)


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


@dataclass
class CircuitBreaker:
    """Fail-fast when a dependency is persistently unhealthy."""

    name: str
    failure_threshold: int = 3
    recovery_timeout_sec: float = 60.0
    _failures: int = 0
    _opened_at: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def is_open(self) -> bool:
        with self._lock:
            return self._is_open_locked()

    def _is_open_locked(self) -> bool:
        if self._failures < self.failure_threshold:
            return False
        if time.time() - self._opened_at >= self.recovery_timeout_sec:
            return False  # half-open probe allowed
        return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = 0.0

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = time.time()
                logger.error(
                    "circuit OPEN for %s after %s failures",
                    self.name,
                    self._failures,
                )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "failures": self._failures,
                "open": self._is_open_locked(),
                "threshold": self.failure_threshold,
                "recovery_timeout_sec": self.recovery_timeout_sec,
            }


# ---------------------------------------------------------------------------
# Last-good cache (graceful degradation reads)
# ---------------------------------------------------------------------------


class LastGoodCache:
    """Thread-safe last-good snapshots for read paths when Postgres is down."""

    def __init__(self, max_search: int = 32) -> None:
        self._lock = threading.Lock()
        self._stats: Optional[dict[str, Any]] = None
        self._health: Optional[dict[str, Any]] = None
        self._search: dict[str, dict[str, Any]] = {}  # query key -> response
        self._search_order: deque[str] = deque()
        self._max_search = max(1, max_search)
        self._updated: dict[str, float] = {}

    def set_stats(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self._stats = dict(payload)
            self._updated["stats"] = time.time()

    def get_stats(self) -> Optional[dict[str, Any]]:
        with self._lock:
            return dict(self._stats) if self._stats is not None else None

    def set_health(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self._health = dict(payload)
            self._updated["health"] = time.time()

    def get_health(self) -> Optional[dict[str, Any]]:
        with self._lock:
            return dict(self._health) if self._health is not None else None


    def set_deployments(self, key: str, payload: dict[str, Any]) -> None:
        """Alias: cache deployments list under a key."""
        self.set_search(key, payload)

    def get_deployments(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(key)

    def set_locks(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self._search["__locks__"] = dict(payload)
            self._updated["locks"] = time.time()

    def get_locks(self) -> Optional[dict[str, Any]]:
        with self._lock:
            body = self._search.get("__locks__")
            return dict(body) if body is not None else None

    def set_search(self, key: str, payload: dict[str, Any]) -> None:
        if not key:
            return
        with self._lock:
            if key in self._search:
                try:
                    self._search_order.remove(key)
                except ValueError:
                    pass
            self._search[key] = dict(payload)
            self._search_order.append(key)
            while len(self._search_order) > self._max_search:
                old = self._search_order.popleft()
                self._search.pop(old, None)
            self._updated["search"] = time.time()

    def get_search(self, key: str) -> Optional[dict[str, Any]]:
        if not key:
            return None
        with self._lock:
            body = self._search.get(key)
            return dict(body) if body is not None else None


    def set_share(self, slug: str, payload: dict[str, Any]) -> None:
        self.set_search(f"share:{slug}", payload)

    def get_share(self, slug: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"share:{slug}")

    def set_kit(self, session_id: str, payload: dict[str, Any]) -> None:
        self.set_search(f"kit:{session_id}", payload)

    def get_kit(self, session_id: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"kit:{session_id}")

    def set_preview(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"preview:{key}", payload)

    def get_preview(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"preview:{key}")



    def set_invoices(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"invoices:{key}", payload)

    def get_invoices(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"invoices:{key}")

    def set_clients(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"clients:{key}", payload)

    def get_clients(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"clients:{key}")

    def set_tenants(self, payload: dict[str, Any]) -> None:
        self.set_search("__tenants__", payload)

    def get_tenants(self) -> Optional[dict[str, Any]]:
        return self.get_search("__tenants__")

    def set_status(self, payload: dict[str, Any]) -> None:
        self.set_search("__status__", payload)

    def get_status(self) -> Optional[dict[str, Any]]:
        return self.get_search("__status__")

    def set_pipelines(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"pipelines:{key}", payload)

    def get_pipelines(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"pipelines:{key}")

    def set_contacts(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"contacts:{key}", payload)

    def get_contacts(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"contacts:{key}")

    def set_companies(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"companies:{key}", payload)

    def get_companies(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"companies:{key}")

    def set_deals(self, key: str, payload: dict[str, Any]) -> None:
        self.set_search(f"deals:{key}", payload)

    def get_deals(self, key: str) -> Optional[dict[str, Any]]:
        return self.get_search(f"deals:{key}")

    def set_plans(self, payload: dict[str, Any]) -> None:
        self.set_search("__plans__", payload)

    def get_plans(self) -> Optional[dict[str, Any]]:
        return self.get_search("__plans__")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "has_stats": self._stats is not None,
                "has_health": self._health is not None,
                "search_entries": len(self._search),
                "updated_at": dict(self._updated),
            }


# ---------------------------------------------------------------------------
# Pending write queue
# ---------------------------------------------------------------------------


@dataclass
class PendingWrite:
    kind: str
    payload: dict[str, Any]
    created_at: float = field(default_factory=time.time)
    attempts: int = 0
    idempotency_key: str = ""


class PendingWriteQueue:
    """Queue DB side-effects when Postgres is down; flush on recovery."""

    def __init__(self, max_entries: int = 2048, spill_path: Optional[str] = None) -> None:
        self._max = max(1, max_entries)
        self._queue: deque[PendingWrite] = deque()
        self._lock = threading.Lock()
        self._spill = spill_path
        self._keys: set[str] = set()
        if self._spill and os.path.isfile(self._spill):
            self._load_spill()

    def _load_spill(self) -> None:
        try:
            with open(self._spill, "r", encoding="utf-8") as fh:  # type: ignore[arg-type]
                raw = json.load(fh)
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, dict) and "kind" in item and "payload" in item:
                        key = str(item.get("idempotency_key", ""))
                        self._queue.append(
                            PendingWrite(
                                kind=item["kind"],
                                payload=item["payload"],
                                created_at=float(item.get("created_at", time.time())),
                                attempts=int(item.get("attempts", 0)),
                                idempotency_key=key,
                            )
                        )
                        if key:
                            self._keys.add(key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("pending write spill load failed: %s", exc)

    def _persist_locked(self) -> None:
        if not self._spill:
            return
        try:
            payload = [
                {
                    "kind": w.kind,
                    "payload": w.payload,
                    "created_at": w.created_at,
                    "attempts": w.attempts,
                    "idempotency_key": w.idempotency_key,
                }
                for w in self._queue
            ]
            atomic_write_json(self._spill, payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("pending write spill failed: %s", exc)

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str = "",
    ) -> bool:
        with self._lock:
            if idempotency_key and idempotency_key in self._keys:
                return True  # already queued — idempotent
            if len(self._queue) >= self._max:
                logger.error("pending queue full (%s)", self._max)
                return False
            self._queue.append(
                PendingWrite(
                    kind=kind,
                    payload=dict(payload),
                    idempotency_key=idempotency_key,
                )
            )
            if idempotency_key:
                self._keys.add(idempotency_key)
            self._persist_locked()
            return True

    def drain(self, handler: Callable[[PendingWrite], bool]) -> tuple[int, int]:
        """Apply pending writes. handler invoked outside the queue lock."""
        with self._lock:
            batch: list[PendingWrite] = []
            while self._queue:
                batch.append(self._queue.popleft())

        applied = 0
        retry: list[PendingWrite] = []
        for item in batch:
            key = item.idempotency_key
            try:
                ok = handler(item)
            except Exception as exc:  # noqa: BLE001
                logger.warning("pending write flush failed (%s): %s", item.kind, exc)
                ok = False
            if ok:
                applied += 1
                if key:
                    with self._lock:
                        self._keys.discard(key)
            else:
                item.attempts += 1
                retry.append(item)

        with self._lock:
            new_q: deque[PendingWrite] = deque()
            for item in retry:
                new_q.append(item)
            while self._queue:
                new_q.append(self._queue.popleft())
            self._queue = new_q
            self._persist_locked()
            return applied, len(self._queue)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)


# ---------------------------------------------------------------------------
# MinIO operation queue
# ---------------------------------------------------------------------------


@dataclass
class MinIOOperation:
    op: str  # put
    key: str
    data: Optional[bytes] = None
    created_at: float = field(default_factory=time.time)
    attempts: int = 0


class MinIOOperationQueue:
    """Queue object uploads when MinIO is unavailable (idempotent per key)."""

    def __init__(self, max_entries: int = 256) -> None:
        self._max = max(1, max_entries)
        self._queue: deque[MinIOOperation] = deque()
        self._lock = threading.Lock()

    def enqueue_put(self, key: str, data: bytes) -> bool:
        with self._lock:
            for item in self._queue:
                if item.op == "put" and item.key == key:
                    item.data = data
                    item.created_at = time.time()
                    return True
            if len(self._queue) >= self._max:
                return False
            self._queue.append(MinIOOperation(op="put", key=key, data=data))
            return True

    def drain(self, put_fn: Callable[[str, bytes], bool]) -> tuple[int, int]:
        applied = 0
        with self._lock:
            remaining: deque[MinIOOperation] = deque()
            while self._queue:
                item = self._queue.popleft()
                try:
                    ok = False
                    if item.op == "put" and item.data is not None:
                        ok = put_fn(item.key, item.data)
                    if ok:
                        applied += 1
                    else:
                        item.attempts += 1
                        remaining.append(item)
                except Exception as exc:  # noqa: BLE001
                    item.attempts += 1
                    logger.warning("minio queue flush failed: %s", exc)
                    remaining.append(item)
            self._queue = remaining
            return applied, len(self._queue)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)


# ---------------------------------------------------------------------------
# Dependency probes
# ---------------------------------------------------------------------------


def probe_http(base_url: str, path: str = "/health", timeout: float = 2.0) -> dict[str, Any]:
    """Probe an HTTP dependency. Returns {ok, latency_ms, detail?}."""
    if not base_url:
        return {"ok": False, "configured": False, "detail": "url not set"}
    url = f"{base_url.rstrip('/')}{path}"
    started = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "echo-invoice/resilience"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(256)
            latency = (time.monotonic() - started) * 1000
            return {
                "ok": True,
                "configured": True,
                "latency_ms": round(latency, 1),
                "status": resp.status,
            }
    except urllib.error.HTTPError as exc:
        latency = (time.monotonic() - started) * 1000
        return {
            "ok": True,
            "configured": True,
            "latency_ms": round(latency, 1),
            "status": exc.code,
        }
    except Exception as exc:  # noqa: BLE001
        latency = (time.monotonic() - started) * 1000
        return {
            "ok": False,
            "configured": True,
            "latency_ms": round(latency, 1),
            "detail": f"{type(exc).__name__}: {str(exc)[:160]}",
        }


def probe_postgres(connect_fn: Callable[[], Any], timeout: float = 3.0) -> dict[str, Any]:
    """Probe Postgres via a connect_fn that returns a live connection."""
    started = time.monotonic()
    con = None
    try:
        con = connect_fn()
        with con.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        latency = (time.monotonic() - started) * 1000
        return {"ok": True, "latency_ms": round(latency, 1)}
    except Exception as exc:  # noqa: BLE001
        latency = (time.monotonic() - started) * 1000
        return {
            "ok": False,
            "latency_ms": round(latency, 1),
            "detail": f"{type(exc).__name__}: {str(exc)[:160]}",
        }
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:  # noqa: BLE001
                pass


def probe_minio(
    endpoint: str,
    access_key: str,
    secret_key: str,
    bucket: str = "",
    secure: bool = False,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Probe MinIO. Uses minio SDK if present, otherwise HTTP health."""
    if not endpoint:
        return {"ok": False, "configured": False, "detail": "MINIO_ENDPOINT not set"}
    started = time.monotonic()
    try:
        from minio import Minio  # type: ignore

        client = Minio(
            endpoint.replace("https://", "").replace("http://", ""),
            access_key=access_key or "minio",
            secret_key=secret_key or "minio123",
            secure=secure or endpoint.startswith("https"),
        )
        list(client.list_buckets())
        latency = (time.monotonic() - started) * 1000
        result: dict[str, Any] = {
            "ok": True,
            "configured": True,
            "latency_ms": round(latency, 1),
        }
        if bucket:
            try:
                result["bucket_exists"] = client.bucket_exists(bucket)
            except Exception as exc:  # noqa: BLE001
                result["bucket_exists"] = False
                result["bucket_detail"] = str(exc)[:120]
        return result
    except ImportError:
        base = endpoint if "://" in endpoint else f"http://{endpoint}"
        res = probe_http(base, path="/minio/health/live", timeout=timeout)
        res["configured"] = True
        res["via"] = "http_health"
        return res
    except Exception as exc:  # noqa: BLE001
        latency = (time.monotonic() - started) * 1000
        return {
            "ok": False,
            "configured": True,
            "latency_ms": round(latency, 1),
            "detail": f"{type(exc).__name__}: {str(exc)[:160]}",
        }


def pg_connect_kwargs() -> dict[str, Any]:
    """psycopg2 connect kwargs with connect_timeout.

    Prefer INV_DSN (used by the live unit) when set; otherwise discrete
    PGHOST/PGUSER/… vars. Always inject connect_timeout so a dead Postgres
    cannot hang library-first callers forever.
    """
    connect_timeout = int(
        os.environ.get("INV_PG_CONNECT_TIMEOUT", os.environ.get("PGCONNECT_TIMEOUT", "5"))
    )
    statement_timeout_ms = int(os.environ.get("INV_PG_STATEMENT_TIMEOUT_MS", "30000"))
    dsn = os.environ.get("INV_DSN", "").strip()
    kwargs: dict[str, Any] = {
        "connect_timeout": connect_timeout,
        "options": f"-c statement_timeout={statement_timeout_ms}",
    }
    if dsn:
        # psycopg2 accepts dsn= as first arg; keep as 'dsn' key for callers that
        # expand kwargs: psycopg2.connect(**kwargs) works with dsn=.
        kwargs["dsn"] = dsn
        return kwargs
    kwargs.update(
        {
            "host": os.environ.get("PGHOST", "127.0.0.1"),
            "user": os.environ.get("PGUSER", "echo"),
            "password": required_env("PGPASSWORD"),
            "dbname": os.environ.get("PGDATABASE", "echo"),
        }
    )
    port = os.environ.get("PGPORT", "5432")
    if port:
        kwargs["port"] = int(port)
    sslmode = os.environ.get("PGSSLMODE")
    if sslmode:
        kwargs["sslmode"] = sslmode
    return kwargs


# ---------------------------------------------------------------------------
# Dependency health + runtime
# ---------------------------------------------------------------------------


@dataclass
class DependencyHealth:
    postgres: dict[str, Any] = field(default_factory=lambda: {"ok": False})
    minio: dict[str, Any] = field(default_factory=lambda: {"ok": False, "configured": False})
    gate: dict[str, Any] = field(default_factory=lambda: {"ok": False, "configured": False})
    mode: str = "unknown"  # healthy | degraded | unavailable
    checked_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "postgres": self.postgres,
            "minio": self.minio,
            "gate": self.gate,
            "mode": self.mode,
            "checked_at": self.checked_at,
            "checked_at_iso": (
                datetime.fromtimestamp(self.checked_at, tz=timezone.utc).isoformat()
                if self.checked_at
                else None
            ),
        }


class ResilienceRuntime:
    """Process-wide resilience runtime for echo-invoice."""

    def __init__(self, state_dir: Optional[str] = None) -> None:
        state_dir = state_dir or os.environ.get(
            "INV_STATE_DIR",
            os.path.join(os.path.expanduser("~"), ".cache", "echo-invoice"),
        )
        os.makedirs(state_dir, exist_ok=True)
        self.state_dir = state_dir
        self.retry_policy = RetryPolicy.from_env()
        self.request_retry = RetryPolicy.request_path()
        self.cache = LastGoodCache(max_search=int(os.environ.get("INV_CACHE_MAX", "32")))
        self.pending_writes = PendingWriteQueue(
            max_entries=int(os.environ.get("INV_PENDING_MAX", "2048")),
            spill_path=os.path.join(state_dir, "pending_writes.json"),
        )
        self.idempotency = IdempotencyStore(
            max_entries=int(os.environ.get("INV_IDEMPOTENCY_MAX", "4096")),
            ttl_sec=float(os.environ.get("INV_IDEMPOTENCY_TTL", "86400")),
            spill_path=os.path.join(state_dir, "idempotency.json"),
        )
        self.minio_queue = MinIOOperationQueue(
            max_entries=int(os.environ.get("INV_MINIO_QUEUE_MAX", "256"))
        )
        # fail_open (default): stay up with last-good + queue when DB down
        self.fail_open = os.environ.get("INV_FAIL_OPEN", "1") not in ("0", "false", "False")
        self._health = DependencyHealth()
        self._health_lock = threading.Lock()
        self._degraded = False
        self._flush_thread: Optional[threading.Thread] = None
        self._probe_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._metrics = {
            "degraded_reads": 0,
            "degraded_writes_queued": 0,
            "idempotent_hits": 0,
            "db_retries": 0,
            "gate_retries": 0,
        }
        self._metrics_lock = threading.Lock()

        self.gate_url = os.environ.get(
            "SDK_GATE_URL",
            os.environ.get("ECHO_SDK_GATE_URL", os.environ.get("ECHO_GATE", "http://127.0.0.1:8000")),
        )
        self.minio_endpoint = os.environ.get("MINIO_ENDPOINT", "")
        self.minio_access = os.environ.get(
            "MINIO_ACCESS_KEY", os.environ.get("MINIO_ROOT_USER", "")
        )
        self.minio_secret = os.environ.get(
            "MINIO_SECRET_KEY", os.environ.get("MINIO_ROOT_PASSWORD", "")
        )
        self.minio_bucket = os.environ.get("MINIO_BUCKET", os.environ.get("INV_MINIO_BUCKET", "echo-invoice"))
        self.minio_secure = os.environ.get("MINIO_SECURE", "0") in ("1", "true", "True")

        self.circuit_pg = CircuitBreaker("postgres")
        self.circuit_gate = CircuitBreaker("gate")
        self.circuit_minio = CircuitBreaker("minio")

    # -- metrics ------------------------------------------------------------
    def _inc(self, name: str, n: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[name] = int(self._metrics.get(name, 0)) + n

    def metrics_snapshot(self) -> dict[str, int]:
        with self._metrics_lock:
            return dict(self._metrics)

    # -- health -------------------------------------------------------------
    def refresh_health(self, connect_fn: Optional[Callable[[], Any]] = None) -> DependencyHealth:
        if connect_fn is not None and not self.circuit_pg.is_open():
            pg = probe_postgres(connect_fn)
            if pg.get("ok"):
                self.circuit_pg.record_success()
            else:
                self.circuit_pg.record_failure()
        elif self.circuit_pg.is_open():
            pg = {"ok": False, "detail": "circuit_open", "circuit": self.circuit_pg.snapshot()}
        else:
            pg = dict(self._health.postgres)

        if self.minio_endpoint and not self.circuit_minio.is_open():
            minio = probe_minio(
                self.minio_endpoint,
                self.minio_access,
                self.minio_secret,
                bucket=self.minio_bucket,
                secure=self.minio_secure,
            )
            if minio.get("ok"):
                self.circuit_minio.record_success()
            else:
                self.circuit_minio.record_failure()
        elif not self.minio_endpoint:
            minio = {"ok": False, "configured": False, "detail": "not configured"}
        else:
            minio = {
                "ok": False,
                "configured": True,
                "detail": "circuit_open",
                "circuit": self.circuit_minio.snapshot(),
            }

        if not self.circuit_gate.is_open():
            gate = probe_http(self.gate_url, path="/health", timeout=2.0)
            gate["configured"] = True
            gate["url"] = self.gate_url
            if gate.get("ok"):
                self.circuit_gate.record_success()
            else:
                self.circuit_gate.record_failure()
        else:
            gate = {
                "ok": False,
                "configured": True,
                "url": self.gate_url,
                "detail": "circuit_open",
                "circuit": self.circuit_gate.snapshot(),
            }

        if pg.get("ok"):
            mode = "healthy"
            self._degraded = False
        elif self.fail_open:
            mode = "degraded"
            self._degraded = True
        else:
            mode = "unavailable"
            self._degraded = True

        health = DependencyHealth(
            postgres=pg,
            minio=minio,
            gate=gate,
            mode=mode,
            checked_at=time.time(),
        )
        with self._health_lock:
            self._health = health
        return health

    def get_health(self) -> DependencyHealth:
        with self._health_lock:
            return DependencyHealth(
                postgres=dict(self._health.postgres),
                minio=dict(self._health.minio),
                gate=dict(self._health.gate),
                mode=self._health.mode,
                checked_at=self._health.checked_at,
            )

    @property
    def degraded(self) -> bool:
        return self._degraded

    def mark_db_down(self) -> None:
        self._degraded = True
        self.circuit_pg.record_failure()
        with self._health_lock:
            self._health.postgres = {"ok": False, "detail": "recent_failure"}
            self._health.mode = "degraded" if self.fail_open else "unavailable"

    def mark_db_up(self) -> None:
        self._degraded = False
        self.circuit_pg.record_success()
        with self._health_lock:
            self._health.postgres = {"ok": True}
            self._health.mode = "healthy"

    # -- write helpers ------------------------------------------------------
    def queue_write(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str = "",
    ) -> bool:
        ok = self.pending_writes.enqueue(kind, payload, idempotency_key=idempotency_key)
        if ok:
            self._inc("degraded_writes_queued")
        return ok

    def remember_idempotent(self, key: str, body: dict[str, Any]) -> None:
        self.idempotency.put(key, body)

    def recall_idempotent(self, key: str) -> Optional[dict[str, Any]]:
        body = self.idempotency.get(key)
        if body is not None:
            self._inc("idempotent_hits")
        return body

    def degraded_read(self, name: str) -> None:
        self._inc("degraded_reads")
        logger.warning("serving last-good %s (degraded)", name)

    def queue_minio_put(self, key: str, data: bytes) -> bool:
        return self.minio_queue.enqueue_put(key, data)

    def try_minio_put(self, key: str, data: bytes, put_fn: Callable[[str, bytes], bool]) -> dict[str, Any]:
        """Best-effort MinIO put with retry; queue on failure."""
        if not self.minio_endpoint:
            return {"ok": False, "configured": False, "queued": False}
        if self.circuit_minio.is_open():
            queued = self.queue_minio_put(key, data)
            return {"ok": False, "configured": True, "queued": queued, "detail": "circuit_open"}

        def _do() -> bool:
            return put_fn(key, data)

        try:
            ok = retry_with_backoff(
                _do,
                self.request_retry,
                op_name=f"minio_put:{key}",
                dependency="minio",
            )
            if ok:
                self.circuit_minio.record_success()
                return {"ok": True, "configured": True, "queued": False, "key": key}
            self.circuit_minio.record_failure()
            queued = self.queue_minio_put(key, data)
            return {"ok": False, "configured": True, "queued": queued}
        except Exception as exc:  # noqa: BLE001
            self.circuit_minio.record_failure()
            queued = self.queue_minio_put(key, data)
            return {
                "ok": False,
                "configured": True,
                "queued": queued,
                "detail": str(exc)[:160],
            }

    # -- background flush / probe -------------------------------------------
    def start_flusher(
        self,
        flush_handler: Callable[[PendingWrite], bool],
        interval_sec: float = 5.0,
    ) -> None:
        if self._flush_thread and self._flush_thread.is_alive():
            return

        def _loop() -> None:
            while not self._stop.wait(interval_sec):
                if self.pending_writes.size == 0:
                    continue
                try:
                    applied, remaining = self.pending_writes.drain(flush_handler)
                    if applied:
                        logger.info(
                            "flushed %s pending writes (%s remaining)",
                            applied,
                            remaining,
                        )
                        self.mark_db_up()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("pending write flusher error: %s", exc)

        self._flush_thread = threading.Thread(
            target=_loop, name="invoice-pending-flush", daemon=True
        )
        self._flush_thread.start()

    def start_probe_loop(
        self,
        connect_fn: Callable[[], Any],
        interval_sec: float = 30.0,
    ) -> None:
        if self._probe_thread and self._probe_thread.is_alive():
            return

        def _loop() -> None:
            while not self._stop.wait(interval_sec):
                try:
                    self.refresh_health(connect_fn)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("dependency probe error: %s", exc)

        self._probe_thread = threading.Thread(
            target=_loop, name="invoice-dep-probe", daemon=True
        )
        self._probe_thread.start()

    def stop(self) -> None:
        self._stop.set()

    def status_dict(self) -> dict[str, Any]:
        health = self.get_health()
        return {
            "service": "echo-invoice",
            "mode": health.mode,
            "degraded": self._degraded,
            "fail_open": self.fail_open,
            "dependencies": health.to_dict(),
            "cache": self.cache.snapshot(),
            "pending_writes": self.pending_writes.size,
            "idempotency_entries": self.idempotency.size,
            "minio_queue": self.minio_queue.size,
            "circuits": {
                "postgres": self.circuit_pg.snapshot(),
                "gate": self.circuit_gate.snapshot(),
                "minio": self.circuit_minio.snapshot(),
            },
            "metrics": self.metrics_snapshot(),
            "retry_policy": {
                "max_attempts": self.retry_policy.max_attempts,
                "base_delay_sec": self.retry_policy.base_delay_sec,
                "max_delay_sec": self.retry_policy.max_delay_sec,
                "jitter": self.retry_policy.jitter,
            },
            "request_retry_policy": {
                "max_attempts": self.request_retry.max_attempts,
                "base_delay_sec": self.request_retry.base_delay_sec,
                "max_delay_sec": self.request_retry.max_delay_sec,
                "jitter": self.request_retry.jitter,
            },
            "state_dir": self.state_dir,
        }


# Module-level singleton used by app.py
runtime = ResilienceRuntime()


def reset_runtime_for_tests(state_dir: Optional[str] = None) -> ResilienceRuntime:
    """Replace the process singleton (tests only)."""
    global runtime
    runtime = ResilienceRuntime(state_dir=state_dir)
    return runtime



__all__ = [
    "RESILIENCE_VERSION",
    "SERVICE_SLUG",
    "CircuitBreaker",
    "DependencyHealth",
    "DependencyUnavailable",
    "IdempotencyStore",
    "LastGoodCache",
    "MinIOOperation",
    "MinIOOperationQueue",
    "PendingWrite",
    "PendingWriteQueue",
    "ResilienceRuntime",
    "RetryPolicy",
    "atomic_write_json",
    "content_hash",
    "is_retryable",
    "pg_connect_kwargs",
    "probe_http",
    "probe_minio",
    "probe_postgres",
    "retry_with_backoff",
    "reset_runtime_for_tests",
    "runtime",
]

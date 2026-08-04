from __future__ import annotations

import os


def required_env(name: str) -> str:
    """Return a non-empty secret setting or abort service startup safely."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"Required environment variable {name} is not configured")
    return value

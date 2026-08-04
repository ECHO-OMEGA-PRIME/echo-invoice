from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

import security


class ServiceAuthenticationTests(unittest.TestCase):
    def test_missing_service_key_returns_503(self) -> None:
        with (
            patch.object(security, "api_key", return_value=""),
            patch.object(security, "_dev_mode", return_value=True),
            self.assertRaises(HTTPException) as raised,
        ):
            security.require_auth("tenants.list", None)
        self.assertEqual(raised.exception.status_code, 503)

    def test_wrong_key_is_rejected_and_configured_key_is_accepted(self) -> None:
        with (
            patch.object(security, "api_key", return_value="test-service-key"),
            patch.object(security, "_dev_mode", return_value=False),
        ):
            with self.assertRaises(HTTPException) as missing:
                security.require_auth("tenants.list", None)
            self.assertEqual(missing.exception.status_code, 401)

            with self.assertRaises(HTTPException) as wrong:
                security.require_auth("tenants.list", "wrong-key")
            self.assertEqual(wrong.exception.status_code, 401)

            result = security.require_auth("tenants.list", "test-service-key")
            self.assertTrue(result["authenticated"])


class WorkerPaymentTokenTests(unittest.TestCase):
    def test_public_invoice_routes_require_hmac_configuration(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "src" / "index.ts").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(source.count("if (!c.env.INVOICE_HMAC_KEY)"), 3)
        self.assertEqual(source.count("constantTimeTokenEqual(token, expected)"), 2)
        self.assertNotIn("if (c.env.INVOICE_HMAC_KEY)", source)

    def test_stripe_webhook_and_worker_auth_fail_closed(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "src" / "index.ts").read_text(
            encoding="utf-8"
        )
        self.assertIn("if (!c.env.STRIPE_WEBHOOK_SECRET)", source)
        self.assertIn("constantTimeTokenEqual(expected, signature)", source)
        self.assertNotIn("skipping signature verification", source)
        self.assertNotIn("method === 'GET' || method === 'OPTIONS'", source)
        self.assertIn("return json({ error: 'Service auth not configured' }, 503)", source)

    def test_python_stripe_webhook_has_no_unsigned_mode(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "app.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("ECHO_INVOICE_ALLOW_UNSIGNED_WEBHOOKS", source)
        self.assertIn('return fail("webhook secret not configured", 503)', source)
        self.assertIn("if not _verify_stripe_signature(body, sig, secret):", source)


if __name__ == "__main__":
    unittest.main()

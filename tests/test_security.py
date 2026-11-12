from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("keynest_v3_security", ROOT / "app.py")
app = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(app)


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Path(self.temp_dir.name) / "security.db"
        app.initialize_database(self.db)
        ok, _, self.user = app.register_user("alice", "DemoPassword123!", self.db)
        self.assertTrue(ok)

    def tearDown(self) -> None:
        for token in list(app.SESSIONS):
            app.destroy_session(token)
        self.temp_dir.cleanup()

    def payload(self) -> dict[str, str]:
        return {
            "site": "敏感测试站点",
            "account": "alice_sensitive@example.test",
            "password": "VaultSecret_987!",
            "url": "https://secure.example.test",
            "notes": "仅为虚构安全测试数据",
        }

    def test_01_master_password_is_salted_and_not_stored(self) -> None:
        # Same password must still produce independent hashes and salts.
        ok, _, _ = app.register_user("bob", "DemoPassword123!", self.db)
        self.assertTrue(ok)
        with app.connect(self.db) as connection:
            rows = connection.execute("SELECT password_hash, auth_salt, vault_salt FROM users ORDER BY id").fetchall()
        serialized = repr([dict(row) for row in rows])
        self.assertNotIn("DemoPassword123!", serialized)
        self.assertNotEqual(rows[0][0], rows[1][0])
        self.assertNotEqual(rows[0][1], rows[1][1])
        self.assertNotEqual(rows[0][1], rows[0][2])

    def test_02_vault_fields_are_encrypted_at_rest(self) -> None:
        app.create_entry(self.user["id"], self.payload(), self.user["vault_key"], self.db)
        with app.connect(self.db) as connection:
            row = connection.execute("SELECT encrypted_blob, nonce FROM vault_entries").fetchone()
        serialized = " ".join(row)
        for secret in self.payload().values():
            self.assertNotIn(secret, serialized)

    def test_03_sql_injection_login_is_rejected(self) -> None:
        attacker = app.authenticate_user("' OR 1=1 -- ", "anything", self.db)
        self.assertIsNone(attacker)

    def test_04_ciphertext_tampering_is_detected(self) -> None:
        entry_id = app.create_entry(self.user["id"], self.payload(), self.user["vault_key"], self.db)
        with app.connect(self.db) as connection:
            connection.execute("UPDATE vault_entries SET encrypted_blob = ? WHERE id = ?", ("AAAA", entry_id))
        with self.assertRaises(app.VaultIntegrityError):
            app.list_entries(self.user["id"], self.user["vault_key"], self.db)

    def test_05_csrf_token_requires_constant_time_match(self) -> None:
        token, csrf = app.create_session(self.user)
        session = app.get_session(token)
        self.assertTrue(app.csrf_is_valid(session, csrf))
        self.assertFalse(app.csrf_is_valid(session, "wrong-token"))
        self.assertFalse(app.csrf_is_valid(session, None))
        self.assertFalse(app.csrf_is_valid(session, "非ASCII令牌"))

    def test_06_login_rate_limiter_blocks_after_threshold(self) -> None:
        limiter = app.LoginLimiter(maximum=3, window_seconds=60, block_seconds=30)
        for moment in (1.0, 2.0, 3.0):
            self.assertTrue(limiter.is_allowed("client", now=moment))
            limiter.record_failure("client", now=moment)
        self.assertFalse(limiter.is_allowed("client", now=4.0))
        self.assertTrue(limiter.is_allowed("client", now=34.0))

    def test_07_session_tokens_are_high_entropy_and_expire(self) -> None:
        token_a, csrf_a = app.create_session(self.user, now=100.0)
        token_b, csrf_b = app.create_session(self.user, now=100.0)
        self.assertNotEqual(token_a, token_b)
        self.assertNotEqual(csrf_a, csrf_b)
        self.assertGreaterEqual(len(token_a), 40)
        self.assertIsNone(app.get_session(token_a, now=100.0 + app.SESSION_TTL_SECONDS + 1))

    def test_12_expired_sessions_release_keys_without_requests(self) -> None:
        expired, _ = app.create_session(self.user, now=100.0)
        active, _ = app.create_session(self.user, now=200.0)
        old_session = app.SESSIONS[expired]
        count = app.cleanup_expired_sessions(now=100.0 + app.SESSION_TTL_SECONDS)
        self.assertEqual(count, 1)
        self.assertNotIn(expired, app.SESSIONS)
        self.assertEqual(old_session["vault_key"], b"")
        self.assertIn(active, app.SESSIONS)

    def test_13_limiter_reclaims_inactive_state(self) -> None:
        limiter = app.LoginLimiter(maximum=1, window_seconds=60, block_seconds=30)
        self.assertTrue(limiter.is_allowed("unseen", now=1.0))
        self.assertNotIn("unseen", limiter._failures)
        limiter.record_failure("failed", now=1.0)
        limiter.cleanup(now=62.0)
        self.assertEqual(limiter._failures, {})
        self.assertEqual(limiter._blocked_until, {})

    def test_14_invalid_json_field_types_are_not_stringified(self) -> None:
        for value in (None, 123, ["secret"], {"password": "secret"}, "\ud800"):
            with self.subTest(value=repr(value)):
                payload = self.payload()
                payload["password"] = value
                with self.assertRaises(app.ValidationError):
                    app.create_entry(self.user["id"], payload, self.user["vault_key"], self.db)
        ok, _, _ = app.register_user("valid_user", None, self.db)
        self.assertFalse(ok)

    def test_08_entry_input_validation_rejects_bad_url_and_oversize(self) -> None:
        bad = self.payload()
        bad["url"] = "javascript:alert(1)"
        with self.assertRaises(app.ValidationError):
            app.create_entry(self.user["id"], bad, self.user["vault_key"], self.db)
        bad = self.payload()
        bad["notes"] = "x" * 1001
        with self.assertRaises(app.ValidationError):
            app.create_entry(self.user["id"], bad, self.user["vault_key"], self.db)

    def test_09_audit_log_never_contains_vault_secrets(self) -> None:
        entry_id = app.create_entry(self.user["id"], self.payload(), self.user["vault_key"], self.db)
        app.update_entry(self.user["id"], entry_id, self.payload(), self.user["vault_key"], self.db)
        logs = app.list_audit_logs(self.user["id"], self.db)
        serialized = repr(logs)
        self.assertNotIn(self.payload()["password"], serialized)
        self.assertNotIn(self.payload()["account"], serialized)

    def test_10_security_headers_cover_browser_baseline(self) -> None:
        headers = app.SECURITY_HEADERS
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual("nosniff", headers["X-Content-Type-Options"])
        self.assertEqual("DENY", headers["X-Frame-Options"])
        self.assertEqual("no-store", headers["Cache-Control"])

    def test_11_source_uses_parameterized_login_query(self) -> None:
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn("WHERE username = ?", source)
        self.assertNotIn("random.randint", source)
        self.assertIn("AESGCM", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

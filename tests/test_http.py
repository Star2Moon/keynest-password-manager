"""HTTP regression tests against a real, temporary loopback server."""

from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import tempfile
import threading
import time
import unittest
from http.cookies import SimpleCookie
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("keynest_http", ROOT / "app.py")
assert SPEC and SPEC.loader
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)


class QuietHandler(app.PasswordManagerHandler):
    def log_message(self, fmt, *args):
        pass


class HttpRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db = Path(cls.temp_dir.name) / "http.db"
        app.initialize_database(cls.db)
        cls.users = []
        for username in ("http_alice", "http_bob"):
            ok, message, user = app.register_user(username, "DemoPassword123!", cls.db)
            if not ok:
                raise RuntimeError(message)
            cls.users.append(user)
        cls.server = app.PasswordManagerServer(("127.0.0.1", 0), QuietHandler, db_path=cls.db)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp_dir.cleanup()

    def setUp(self):
        self.sessions = [app.create_session(user) for user in self.users]

    def tearDown(self):
        for token in list(app.SESSIONS):
            app.destroy_session(token)
        with app.connect(self.db) as connection:
            connection.execute("DELETE FROM vault_entries")

    def request(self, method, path, payload=None, *, session=None, csrf=True, raw=None, headers=None):
        request_headers = {"Content-Type": "application/json"}
        if session is not None:
            token, csrf_token = self.sessions[session]
            request_headers["Cookie"] = f"session={token}"
            if csrf:
                request_headers["X-CSRF-Token"] = csrf_token if csrf is True else csrf
        request_headers.update(headers or {})
        body = raw if raw is not None else json.dumps(payload or {}).encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            connection.close()

    @staticmethod
    def payload():
        return {"site": "HTTP test", "account": "fictional@example.test", "password": "FictionalOnly123!", "url": "https://example.test", "notes": "test fixture"}

    def test_authentication_cookie_and_logout(self):
        status, headers, body = self.request("POST", "/api/login", {"username": "http_alice", "password": "DemoPassword123!"})
        self.assertEqual(status, 200)
        cookie = SimpleCookie(headers["Set-Cookie"])
        self.assertTrue(cookie["session"]["httponly"])
        self.assertEqual(cookie["session"]["samesite"], "Strict")
        self.assertEqual(int(cookie["session"]["max-age"]), app.SESSION_TTL_SECONDS)
        self.sessions[0] = (cookie["session"].value, body["csrfToken"])
        status, headers, body = self.request("GET", "/api/session", session=0)
        self.assertEqual(status, 200)
        self.assertTrue(body["authenticated"])
        self.assertIn("Set-Cookie", headers)  # sliding server TTL and browser TTL stay aligned
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        status, _, _ = self.request("POST", "/api/logout", session=0, csrf=False)
        self.assertEqual(status, 403)
        status, headers, _ = self.request("POST", "/api/logout", session=0)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        status, _, _ = self.request("GET", "/api/entries", session=0)
        self.assertEqual(status, 401)

    def test_registration_and_session_rotation(self):
        old_token = self.sessions[0][0]
        status, headers, body = self.request("POST", "/api/register", {"username": "http_registered", "password": "DemoPassword123!"}, session=0)
        self.assertEqual(status, 201)
        self.assertTrue(body["csrfToken"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertNotIn(old_token, app.SESSIONS)
        status, _, _ = self.request("POST", "/api/register", {"username": "HTTP_REGISTERED", "password": "DemoPassword123!"})
        self.assertEqual(status, 400)

    def test_crud_csrf_and_cross_user_isolation(self):
        status, _, _ = self.request("GET", "/api/entries")
        self.assertEqual(status, 401)
        for csrf in (False, "wrong-token", "\xe9"):
            status, _, _ = self.request("POST", "/api/entries", self.payload(), session=0, csrf=csrf)
            self.assertEqual(status, 403)
        status, _, body = self.request("POST", "/api/entries", self.payload(), session=0)
        self.assertEqual(status, 201)
        path = f"/api/entries/{body['id']}"
        status, _, body = self.request("GET", "/api/entries", session=1)
        self.assertEqual((status, body["entries"]), (200, []))
        for method in ("PUT", "DELETE"):
            status, _, _ = self.request(method, path, self.payload(), session=1)
            self.assertEqual(status, 404)
        updated = {**self.payload(), "site": "Updated"}
        status, _, _ = self.request("PUT", path, updated, session=0)
        self.assertEqual(status, 200)
        status, _, body = self.request("GET", "/api/entries", session=0)
        self.assertEqual(body["entries"][0]["site"], "Updated")
        self.assertEqual(body["entries"][0]["password"], updated["password"])
        status, _, _ = self.request("DELETE", path, session=0)
        self.assertEqual(status, 200)
        status, _, body = self.request("GET", "/api/entries", session=0)
        self.assertEqual(body["entries"], [])

    def test_invalid_json_and_http_framing_are_client_errors(self):
        cases = [
            (b"{", {}),
            (b"\xff", {}),
            (b"[]", {}),
            (b"{}", {"Content-Type": "text/plain"}),
            (b"{}", {"Content-Length": "nope"}),
            (b"{}", {"Content-Length": "-1"}),
            (b"{}", {"Content-Length": str(app.MAX_BODY_BYTES + 1)}),
            (b"{}", {"Transfer-Encoding": "chunked"}),
        ]
        for raw, headers in cases:
            with self.subTest(headers=headers, raw=raw):
                status, _, _ = self.request("POST", "/api/login", raw=raw, headers=headers)
                self.assertEqual(status, 400)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as connection:
            connection.sendall(b"POST /api/login HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}")
            self.assertIn(b" 400 ", connection.recv(4096).split(b"\r\n", 1)[0])

    def test_field_types_and_unknown_routes(self):
        for password in (None, ["not a password"], {"value": "secret"}, "x" * 129):
            status, _, _ = self.request("POST", "/api/login", {"username": "http_alice", "password": password})
            self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/entries", {**self.payload(), "password": None}, session=0)
        self.assertEqual(status, 400)
        for method in ("POST", "PUT", "DELETE"):
            status, _, _ = self.request(method, "/not-an-api-route", session=0)
            self.assertEqual(status, 404)

    def test_server_loop_reclaims_idle_sessions(self):
        token = self.sessions[0][0]
        with app.SESSION_LOCK:
            app.SESSIONS[token]["expires_at"] = time.time() - 1
        deadline = time.monotonic() + 2
        while token in app.SESSIONS and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertNotIn(token, app.SESSIONS)

    def test_failed_login_is_rate_limited_over_http(self):
        payload = {"username": "http_alice", "password": "IncorrectPassword123!"}
        key = "127.0.0.1:http_alice"
        app.LOGIN_LIMITER.record_success(key)
        try:
            for _ in range(app.LOGIN_LIMITER.maximum):
                status, _, _ = self.request("POST", "/api/login", payload)
                self.assertEqual(status, 401)
            status, _, _ = self.request("POST", "/api/login", payload)
            self.assertEqual(status, 429)
        finally:
            app.LOGIN_LIMITER.record_success(key)


if __name__ == "__main__":
    unittest.main(verbosity=2)

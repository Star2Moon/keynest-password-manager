from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("keynest_v3_functional", ROOT / "app.py")
app = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(app)


class FunctionalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Path(self.temp_dir.name) / "test.db"
        app.initialize_database(self.db)
        app.SESSIONS.clear()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def register(self, username: str = "alice", password: str = "DemoPassword123!"):
        ok, _, user = app.register_user(username, password, self.db)
        self.assertTrue(ok)
        self.assertIsNotNone(user)
        return user

    def payload(self, site: str = "示例邮箱") -> dict[str, str]:
        return {
            "site": site,
            "account": "alice@example.test",
            "password": "FakeSecret!1",
            "url": "https://example.test",
            "notes": "课程测试",
        }

    def test_01_register_user(self) -> None:
        ok, message, user = app.register_user("alice", "DemoPassword123!", self.db)
        self.assertTrue(ok)
        self.assertEqual("注册成功", message)
        self.assertEqual("alice", user["username"])

    def test_02_duplicate_username_is_rejected(self) -> None:
        self.register()
        ok, message, _ = app.register_user("ALICE", "AnotherPass456!", self.db)
        self.assertFalse(ok)
        self.assertIn("已存在", message)

    def test_03_login_accepts_valid_and_rejects_wrong_password(self) -> None:
        self.register()
        self.assertIsNotNone(app.authenticate_user("alice", "DemoPassword123!", self.db))
        self.assertIsNone(app.authenticate_user("alice", "wrong", self.db))

    def test_04_create_and_list_entry(self) -> None:
        user = self.register()
        entry_id = app.create_entry(user["id"], self.payload(), user["vault_key"], self.db)
        entries = app.list_entries(user["id"], user["vault_key"], self.db)
        self.assertEqual(1, len(entries))
        self.assertEqual(entry_id, entries[0]["id"])
        self.assertEqual("示例邮箱", entries[0]["site"])

    def test_05_update_entry(self) -> None:
        user = self.register()
        entry_id = app.create_entry(user["id"], self.payload("旧名称"), user["vault_key"], self.db)
        self.assertTrue(app.update_entry(user["id"], entry_id, self.payload("新名称"), user["vault_key"], self.db))
        self.assertEqual("新名称", app.list_entries(user["id"], user["vault_key"], self.db)[0]["site"])

    def test_06_delete_entry(self) -> None:
        user = self.register()
        entry_id = app.create_entry(user["id"], self.payload("临时"), user["vault_key"], self.db)
        self.assertTrue(app.delete_entry(user["id"], entry_id, self.db))
        self.assertEqual([], app.list_entries(user["id"], user["vault_key"], self.db))

    def test_07_users_cannot_modify_each_others_entries(self) -> None:
        alice = self.register("alice", "DemoPassword123!")
        bob = self.register("bob", "DemoPassword456!")
        entry_id = app.create_entry(alice["id"], self.payload("Alice 专用"), alice["vault_key"], self.db)
        self.assertFalse(app.update_entry(bob["id"], entry_id, self.payload("越权修改"), bob["vault_key"], self.db))
        self.assertFalse(app.delete_entry(bob["id"], entry_id, self.db))
        self.assertEqual("Alice 专用", app.list_entries(alice["id"], alice["vault_key"], self.db)[0]["site"])

    def test_08_session_create_and_logout(self) -> None:
        user = self.register()
        token, csrf_token = app.create_session(user)
        self.assertEqual(csrf_token, app.get_session(token)["csrf_token"])
        app.destroy_session(token)
        self.assertIsNone(app.get_session(token))

    def test_09_frontend_uses_web_crypto_password_generator(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("crypto.getRandomValues", source)
        self.assertIn("generatePassword", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""KeyNest：用于学习与本机演示的密码管理器。

零 Web 框架依赖；使用 Python 标准库提供 HTTP/SQLite 能力，使用
cryptography 的 AES-256-GCM 对保险库内容进行认证加密。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path(os.environ.get("PM_DB_PATH", BASE_DIR / "data" / "vault_v3.db"))
HOST = os.environ.get("PM_HOST", "127.0.0.1")
PORT = int(os.environ.get("PM_PORT", "8080"))
SECURE_COOKIE = os.environ.get("PM_SECURE_COOKIE", "0") == "1"
SESSION_TTL_SECONDS = 30 * 60
MAX_BODY_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 10
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 5
SCRYPT_DKLEN = 32
MAX_ENTRY_SECRET_CHARS = 512

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


class ValidationError(ValueError):
    """客户端提交数据不符合安全约束。"""


class VaultIntegrityError(RuntimeError):
    """密文认证失败，表示数据库内容可能被篡改。"""


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


@contextmanager
def connect(db_path: Path | str = DB_PATH) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(str(db_path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database(db_path: Path | str = DB_PATH) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                auth_salt TEXT NOT NULL,
                vault_salt TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                encrypted_blob TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_vault_user_updated
                ON vault_entries(user_id, updated_at DESC);
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                entry_id TEXT,
                detail TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_user_created
                ON audit_logs(user_id, created_at DESC);
            """
        )


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )


def _validate_credentials(username: str, password: str) -> tuple[str, str]:
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValidationError("用户名和密码必须是字符串")
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValidationError("用户名需为 3-32 位字母、数字或下划线")
    if not 12 <= len(password) <= 128:
        raise ValidationError("主密码长度需为 12-128 位")
    try:
        password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError("主密码包含无效的 Unicode 字符") from exc
    categories = sum(
        bool(pattern.search(password))
        for pattern in (re.compile(r"[a-z]"), re.compile(r"[A-Z]"), re.compile(r"\d"), re.compile(r"[^A-Za-z0-9]"))
    )
    if categories < 3:
        raise ValidationError("主密码至少包含三类字符")
    return username, password


def _audit(
    connection: sqlite3.Connection,
    user_id: int | None,
    action: str,
    entry_id: str | None = None,
    detail: str = "ok",
) -> None:
    connection.execute(
        "INSERT INTO audit_logs(user_id, action, entry_id, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, action[:40], entry_id, detail[:80], int(time.time())),
    )


def register_user(
    username: str, password: str, db_path: Path | str = DB_PATH
) -> tuple[bool, str, dict[str, Any] | None]:
    try:
        username, password = _validate_credentials(username, password)
    except ValidationError as exc:
        return False, str(exc), None
    auth_salt = secrets.token_bytes(16)
    vault_salt = secrets.token_bytes(16)
    password_hash = _derive_key(password, auth_salt)
    vault_key = _derive_key(password, vault_salt)
    try:
        with connect(db_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO users(username, password_hash, auth_salt, vault_salt, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    b64encode(password_hash),
                    b64encode(auth_salt),
                    b64encode(vault_salt),
                    int(time.time()),
                ),
            )
            user_id = int(cursor.lastrowid)
            _audit(connection, user_id, "register")
        return True, "注册成功", {"id": user_id, "username": username, "vault_key": vault_key}
    except sqlite3.IntegrityError:
        return False, "用户名已存在", None


def authenticate_user(
    username: str, password: str, db_path: Path | str = DB_PATH
) -> dict[str, Any] | None:
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    username = username.strip()
    if len(username) > 32 or not 1 <= len(password) <= 128:
        return None
    try:
        username.encode("utf-8")
        password.encode("utf-8")
    except UnicodeEncodeError:
        return None
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, auth_salt, vault_salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            # 对不存在账号也执行同成本计算，降低用户名枚举与时序差异。
            _derive_key(password[:128] or "x", secrets.token_bytes(16))
            return None
        candidate = _derive_key(password, b64decode(str(row["auth_salt"])))
        if not hmac.compare_digest(candidate, b64decode(str(row["password_hash"]))):
            return None
        _audit(connection, int(row["id"]), "login")
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "vault_key": _derive_key(password, b64decode(str(row["vault_salt"]))),
        }


def _validate_entry(payload: dict[str, Any]) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise ValidationError("记录必须是 JSON 对象")
    fields = {}
    for name in ("site", "account", "password", "url", "notes"):
        value = payload.get(name, "")
        if not isinstance(value, str):
            raise ValidationError(f"字段 {name} 必须是字符串")
        fields[name] = value if name == "password" else value.strip()
    limits = {"site": 100, "account": 200, "url": 500, "notes": 1000}
    if not fields["site"] or not fields["account"] or not fields["password"]:
        raise ValidationError("网站、账号和密码不能为空")
    for name, value in fields.items():
        field_limit = MAX_ENTRY_SECRET_CHARS if name == "password" else limits[name]
        if len(value) > field_limit:
            raise ValidationError(f"字段 {name} 超过长度限制")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValidationError(f"字段 {name} 包含无效的 Unicode 字符") from exc
        if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
            raise ValidationError(f"字段 {name} 包含控制字符")
    if fields["url"]:
        try:
            parsed = urlparse(fields["url"])
            valid = parsed.scheme in {"http", "https"} and parsed.hostname and parsed.port != 0
        except ValueError:
            valid = False
        if not valid or any(char.isspace() for char in fields["url"]):
            raise ValidationError("网址只允许有效的 http/https 地址")
    return fields


def _encrypt_entry(user_id: int, entry_id: str, payload: dict[str, str], vault_key: bytes) -> tuple[str, str]:
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    aad = f"keynest:v3:{user_id}:{entry_id}".encode("utf-8")
    ciphertext = AESGCM(vault_key).encrypt(nonce, plaintext, aad)
    return b64encode(ciphertext), b64encode(nonce)


def _decrypt_entry(
    user_id: int, entry_id: str, encrypted_blob: str, nonce: str, vault_key: bytes
) -> dict[str, str]:
    aad = f"keynest:v3:{user_id}:{entry_id}".encode("utf-8")
    try:
        plaintext = AESGCM(vault_key).decrypt(b64decode(nonce), b64decode(encrypted_blob), aad)
    except (InvalidTag, ValueError) as exc:
        raise VaultIntegrityError("保险库数据完整性校验失败") from exc
    value = json.loads(plaintext.decode("utf-8"))
    if not isinstance(value, dict):
        raise VaultIntegrityError("保险库数据格式无效")
    return {key: str(value.get(key, "")) for key in ("site", "account", "password", "url", "notes")}


def create_entry(
    user_id: int,
    payload: dict[str, Any],
    vault_key: bytes,
    db_path: Path | str = DB_PATH,
) -> str:
    clean = _validate_entry(payload)
    entry_id = str(uuid.uuid4())
    encrypted_blob, nonce = _encrypt_entry(user_id, entry_id, clean, vault_key)
    now = int(time.time())
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO vault_entries(id, user_id, encrypted_blob, nonce, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (entry_id, user_id, encrypted_blob, nonce, now, now),
        )
        _audit(connection, user_id, "entry_create", entry_id)
    return entry_id


def list_entries(
    user_id: int, vault_key: bytes, db_path: Path | str = DB_PATH
) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, encrypted_blob, nonce, created_at, updated_at
            FROM vault_entries WHERE user_id = ? ORDER BY updated_at DESC, id DESC
            """,
            (user_id,),
        ).fetchall()
    entries: list[dict[str, Any]] = []
    for row in rows:
        clear = _decrypt_entry(user_id, str(row["id"]), str(row["encrypted_blob"]), str(row["nonce"]), vault_key)
        clear.update({"id": str(row["id"]), "created_at": int(row["created_at"]), "updated_at": int(row["updated_at"])})
        entries.append(clear)
    return entries


def update_entry(
    user_id: int,
    entry_id: str,
    payload: dict[str, Any],
    vault_key: bytes,
    db_path: Path | str = DB_PATH,
) -> bool:
    clean = _validate_entry(payload)
    encrypted_blob, nonce = _encrypt_entry(user_id, entry_id, clean, vault_key)
    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE vault_entries SET encrypted_blob = ?, nonce = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (encrypted_blob, nonce, int(time.time()), entry_id, user_id),
        )
        if cursor.rowcount == 1:
            _audit(connection, user_id, "entry_update", entry_id)
        return cursor.rowcount == 1


def delete_entry(
    user_id: int, entry_id: str, db_path: Path | str = DB_PATH
) -> bool:
    with connect(db_path) as connection:
        cursor = connection.execute(
            "DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
            (entry_id, user_id),
        )
        if cursor.rowcount == 1:
            _audit(connection, user_id, "entry_delete", entry_id)
        return cursor.rowcount == 1


def list_audit_logs(user_id: int, db_path: Path | str = DB_PATH) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT action, entry_id, detail, created_at FROM audit_logs
            WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 50
            """,
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


class LoginLimiter:
    def __init__(self, maximum: int = 5, window_seconds: int = 300, block_seconds: int = 60):
        self.maximum = maximum
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._failures: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, now: float | None = None) -> bool:
        moment = time.time() if now is None else now
        with self._lock:
            if self._blocked_until.get(key, 0) > moment:
                return False
            return True

    def record_failure(self, key: str, now: float | None = None) -> None:
        moment = time.time() if now is None else now
        with self._lock:
            failures = [item for item in self._failures.get(key, []) if item > moment - self.window_seconds]
            failures.append(moment)
            self._failures[key] = failures
            if len(failures) >= self.maximum:
                self._blocked_until[key] = moment + self.block_seconds

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)

    def cleanup(self, now: float | None = None) -> None:
        moment = time.time() if now is None else now
        with self._lock:
            for key, failures in list(self._failures.items()):
                recent = [item for item in failures if item > moment - self.window_seconds]
                if recent:
                    self._failures[key] = recent
                else:
                    self._failures.pop(key, None)
            for key, until in list(self._blocked_until.items()):
                if until <= moment:
                    self._blocked_until.pop(key, None)


LOGIN_LIMITER = LoginLimiter()
SESSIONS: dict[str, dict[str, Any]] = {}
SESSION_LOCK = threading.RLock()


def create_session(user: dict[str, Any], now: float | None = None) -> tuple[str, str]:
    moment = time.time() if now is None else now
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    with SESSION_LOCK:
        SESSIONS[token] = {
            "user_id": int(user["id"]),
            "username": str(user["username"]),
            "vault_key": bytes(user["vault_key"]),
            "csrf_token": csrf_token,
            "expires_at": moment + SESSION_TTL_SECONDS,
        }
    return token, csrf_token


def get_session(token: str | None, now: float | None = None) -> dict[str, Any] | None:
    if not token:
        return None
    moment = time.time() if now is None else now
    with SESSION_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        if float(session["expires_at"]) <= moment:
            destroy_session(token)
            return None
        session["expires_at"] = moment + SESSION_TTL_SECONDS
        return dict(session)


def destroy_session(token: str | None) -> None:
    if token:
        with SESSION_LOCK:
            session = SESSIONS.pop(token, None)
            if session and isinstance(session.get("vault_key"), bytes):
                # Drop the reference, not guaranteed memory zeroization in Python.
                session["vault_key"] = b""


def cleanup_expired_sessions(now: float | None = None) -> int:
    """Release idle vault-key references even when a closed tab makes no request."""
    moment = time.time() if now is None else now
    with SESSION_LOCK:
        expired = [token for token, value in SESSIONS.items() if value["expires_at"] <= moment]
        for token in expired:
            destroy_session(token)
    return len(expired)


def csrf_is_valid(session: dict[str, Any], provided: str | None) -> bool:
    expected = str(session.get("csrf_token", ""))
    return isinstance(provided, str) and bool(provided) and hmac.compare_digest(
        expected.encode("utf-8"), provided.encode("utf-8")
    )


class PasswordManagerServer(ThreadingHTTPServer):
    """Local demo server; the service loop also reclaims expired secrets."""

    def __init__(self, server_address: tuple[str, int], handler_class=None, *, db_path: Path | str = DB_PATH):
        self.db_path = Path(db_path)
        super().__init__(server_address, handler_class or PasswordManagerHandler)

    def service_actions(self) -> None:
        cleanup_expired_sessions()
        LOGIN_LIMITER.cleanup()


class PasswordManagerHandler(BaseHTTPRequestHandler):
    server_version = "KeyNest"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    @property
    def db_path(self) -> Path:
        return Path(getattr(self.server, "db_path", DB_PATH))

    def log_message(self, fmt: str, *args: Any) -> None:
        # BaseHTTPRequestHandler 只记录方法、路径和状态，不记录请求体/凭据。
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def _json_body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ValidationError("不支持 Transfer-Encoding")
        if self.headers.get_content_type() != "application/json":
            raise ValidationError("Content-Type 必须为 application/json")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10:
            raise ValidationError("需要一个有效的 Content-Length")
        length = int(lengths[0])
        if length > MAX_BODY_BYTES:
            raise ValidationError("请求体超过限制")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValidationError("请求体不完整")
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("请求体必须为有效的 UTF-8 JSON") from exc
        except TimeoutError as exc:
            raise ValidationError("读取请求体超时") from exc
        if not isinstance(value, dict):
            raise ValidationError("JSON 必须是对象")
        return value

    def _begin_response(
        self, status: int, content_type: str, length: int, set_cookie: str | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        if set_cookie is None and getattr(self, "_renew_session_token", None):
            set_cookie = self._cookie(self._renew_session_token)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _send_json(
        self, status: int, payload: dict[str, Any], set_cookie: str | None = None
    ) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._begin_response(status, "application/json; charset=utf-8", len(data), set_cookie)
        self.wfile.write(data)

    def _session_token(self) -> str | None:
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookie.get("session")
        return morsel.value if morsel else None

    def _require_session(self, mutate: bool = False) -> dict[str, Any] | None:
        token = self._session_token()
        session = get_session(token)
        if not session:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "请先登录"})
            return None
        if mutate and not csrf_is_valid(session, self.headers.get("X-CSRF-Token")):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF 校验失败"})
            return None
        self._renew_session_token = token
        return session

    def _cookie(self, token: str, clear: bool = False) -> str:
        value = "" if clear else token
        max_age = 0 if clear else SESSION_TTL_SECONDS
        secure = "; Secure" if SECURE_COOKIE else ""
        return f"session={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}"

    def _serve_static(self, relative: str) -> None:
        target = (STATIC_DIR / relative).resolve()
        if STATIC_DIR.resolve() not in target.parents or not target.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "资源不存在"})
            return
        content = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self._begin_response(HTTPStatus.OK, content_type, len(content))
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._serve_static("index.html")
            return
        if path.startswith("/static/"):
            self._serve_static(path.removeprefix("/static/"))
            return
        if path == "/api/session":
            token = self._session_token()
            session = get_session(token)
            if session:
                self._renew_session_token = token
            self._send_json(HTTPStatus.OK, {
                "authenticated": bool(session),
                "username": session.get("username") if session else None,
                "csrfToken": session.get("csrf_token") if session else None,
            })
            return
        if path == "/api/entries":
            session = self._require_session()
            if not session:
                return
            try:
                entries = list_entries(int(session["user_id"]), bytes(session["vault_key"]), self.db_path)
                self._send_json(HTTPStatus.OK, {"entries": entries})
            except VaultIntegrityError:
                with connect(self.db_path) as connection:
                    _audit(connection, int(session["user_id"]), "integrity_failure", detail="ciphertext_rejected")
                self._send_json(HTTPStatus.CONFLICT, {"error": "检测到保险库数据完整性异常"})
            except Exception:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器处理失败"})
            return
        if path == "/api/audit":
            session = self._require_session()
            if session:
                try:
                    self._send_json(HTTPStatus.OK, {"logs": list_audit_logs(int(session["user_id"]), self.db_path)})
                except Exception:
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器处理失败"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path not in {"/api/register", "/api/login", "/api/logout", "/api/entries"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})
            return
        try:
            body = self._json_body()
            if path in {"/api/register", "/api/login"}:
                username = body.get("username", "")
                password = body.get("password", "")
                if not isinstance(username, str) or not isinstance(password, str):
                    raise ValidationError("用户名和密码必须是字符串")
                username = username.strip()
                if len(username) > 32 or not 1 <= len(password) <= 128:
                    raise ValidationError("用户名或密码长度不符合要求")
            if path == "/api/register":
                ok, message, user = register_user(username, password, self.db_path)
                if not ok or not user:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": message})
                    return
                destroy_session(self._session_token())
                token, csrf_token = create_session(user)
                self._send_json(HTTPStatus.CREATED, {"message": message, "username": user["username"], "csrfToken": csrf_token}, self._cookie(token))
                return
            if path == "/api/login":
                limiter_key = f"{self.client_address[0]}:{username.casefold()}"
                if not LOGIN_LIMITER.is_allowed(limiter_key):
                    self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "尝试次数过多，请稍后再试"})
                    return
                user = authenticate_user(username, password, self.db_path)
                if not user:
                    LOGIN_LIMITER.record_failure(limiter_key)
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "用户名或密码错误"})
                    return
                LOGIN_LIMITER.record_success(limiter_key)
                destroy_session(self._session_token())
                token, csrf_token = create_session(user)
                self._send_json(HTTPStatus.OK, {"message": "登录成功", "username": user["username"], "csrfToken": csrf_token}, self._cookie(token))
                return
            if path == "/api/logout":
                session = self._require_session(mutate=True)
                if not session:
                    return
                token = self._session_token()
                destroy_session(token)
                self._send_json(HTTPStatus.OK, {"message": "已退出"}, self._cookie("", clear=True))
                return
            if path == "/api/entries":
                session = self._require_session(mutate=True)
                if not session:
                    return
                entry_id = create_entry(int(session["user_id"]), body, bytes(session["vault_key"]), self.db_path)
                self._send_json(HTTPStatus.CREATED, {"message": "已安全保存", "id": entry_id})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})
        except (ValidationError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器处理失败"})

    def do_PUT(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not path.startswith("/api/entries/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})
            return
        session = self._require_session(mutate=True)
        if not session:
            return
        try:
            entry_id = path.removeprefix("/api/entries/")
            uuid.UUID(entry_id)
            ok = update_entry(int(session["user_id"]), entry_id, self._json_body(), bytes(session["vault_key"]), self.db_path)
            self._send_json(HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"message": "已更新"} if ok else {"error": "记录不存在"})
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "参数错误"})
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器处理失败"})

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not path.startswith("/api/entries/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})
            return
        session = self._require_session(mutate=True)
        if not session:
            return
        try:
            entry_id = path.removeprefix("/api/entries/")
            uuid.UUID(entry_id)
            ok = delete_entry(int(session["user_id"]), entry_id, self.db_path)
            self._send_json(HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"message": "已删除"} if ok else {"error": "记录不存在"})
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "参数错误"})
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器处理失败"})


def main() -> None:
    initialize_database()
    server = PasswordManagerServer((HOST, PORT))
    print(f"KeyNest 已启动：http://{HOST}:{PORT}")
    print("仅用于学习和本机演示；请勿直接暴露到公网或保存真实重要密码。")
    if not SECURE_COOKIE:
        print("本地 HTTP 模式：Cookie 未设置 Secure；这不是可直接用于生产的部署。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

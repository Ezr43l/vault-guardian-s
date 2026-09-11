"""Usuarios locales, sesiones firmadas y segundo factor de Vault Guardian."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import struct
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet, InvalidToken

import http_client
from config import write_portal_access


COOKIE_NAME = "vault_guardian_session"
USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{2,63}")
ATTEMPT_WINDOW_SECONDS = 300
ATTEMPT_LIMIT_PER_USER = 8
ATTEMPT_LIMIT_PER_ORIGIN = 64
ATTEMPT_KEY_LIMIT = 4096
COMMON_PASSWORDS = {
    "123456789012",
    "administrador",
    "changeme1234",
    "password1234",
    "vaultguardian",
    "vault-guardian",
}
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
PASSWORD_SALT_BYTES = 16
PASSWORD_HASH_BYTES = 32
MAX_USERS = 256
MAX_SECURITY_REVISION = 2**63 - 1


class SecurityError(ValueError):
    """Error de autenticación o gestión de identidad apto para la API."""

    def __init__(self, message: str, code: str = "INVALID_CREDENTIALS",
                 status: int = 401):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Identity:
    username: str
    display_name: str
    csrf: str
    expires_at: int
    session_version: int


def normalize_username(value: object) -> str:
    username = str(value or "").strip()
    if not USERNAME.fullmatch(username):
        raise SecurityError(
            "El usuario debe tener entre 3 y 64 caracteres válidos",
            "INVALID_USER", 422)
    return username


def validate_password(password: str, username: str = "") -> None:
    if len(password or "") < 12:
        raise SecurityError(
            "La contraseña debe tener al menos 12 caracteres",
            "WEAK_PASSWORD", 422)
    if len(password) > 256:
        raise SecurityError(
            "La contraseña no puede superar 256 caracteres",
            "WEAK_PASSWORD", 422)
    normalized = password.strip().casefold()
    if normalized in COMMON_PASSWORDS or (
        username and normalized == username.casefold()
    ):
        raise SecurityError(
            "La contraseña elegida es demasiado predecible",
            "WEAK_PASSWORD", 422)


def _decode_urlsafe(value: str) -> bytes:
    return base64.b64decode(
        (value + "=" * (-len(value) % 4)).encode("ascii"),
        altchars=b"-_",
        validate=True,
    )


def _password_components(stored: object) -> tuple[bytes, bytes] | None:
    if not isinstance(stored, str) or len(stored) > 256:
        return None
    try:
        algorithm, n, r, p, salt, expected = stored.split("$", 5)
        if (
            algorithm != "scrypt"
            or (n, r, p) != (str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P))
            or not re.fullmatch(r"[A-Za-z0-9_-]+", salt)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", expected)
        ):
            return None
        salt_bytes = _decode_urlsafe(salt)
        expected_bytes = _decode_urlsafe(expected)
        if (
            len(salt_bytes) != PASSWORD_SALT_BYTES
            or len(expected_bytes) != PASSWORD_HASH_BYTES
        ):
            return None
        return salt_bytes, expected_bytes
    except (TypeError, ValueError, UnicodeError, binascii.Error):
        return None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
        p=SCRYPT_P, dklen=PASSWORD_HASH_BYTES, maxmem=64 * 1024 * 1024)
    return "$".join((
        "scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P),
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(derived).decode().rstrip("="),
    ))


def verify_password(password: str, stored: str) -> bool:
    if not isinstance(password, str) or len(password) > 256:
        return False
    components = _password_components(stored)
    if components is None:
        return False
    salt, expected = components
    try:
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=PASSWORD_HASH_BYTES,
            maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError, UnicodeError, OverflowError, MemoryError):
        return False


def _totp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(
        (secret + "=" * (-len(secret) % 8)).encode(), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: object, now: float | None = None,
                window: int = 1) -> bool:
    candidate = re.sub(r"\s+", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", candidate):
        return False
    counter = int(time.time() if now is None else now) // 30
    return any(
        hmac.compare_digest(candidate, _totp(secret, counter + offset))
        for offset in range(-window, window + 1)
    )


class SecurityManager:
    """Mantiene identidades locales y las distribuye entre Guardian."""

    def __init__(self, settings):
        self.path = Path(getattr(settings, "state_dir", "/state")) / "auth.json"
        self._peers = dict(getattr(settings, "peers", {}) or {})
        self.replication_token = str(
            getattr(settings, "replication_token", "") or "")
        self.session_minutes = max(
            5, min(480, int(getattr(settings, "session_minutes", 30))))
        self.allow_insecure = bool(
            getattr(settings, "allow_insecure_portal", False))
        self.allow_insecure_http = bool(
            getattr(settings, "allow_insecure_http", False))
        self.ca_file = getattr(settings, "ca_file", None)
        self._lock = threading.RLock()
        self._attempts: dict[str, list[float]] = {}
        self._last_attempt_prune = 0.0
        self._session_key = hmac.new(
            self.replication_token.encode(),
            b"vault-guardian/session/v1",
            hashlib.sha256,
        ).digest() if self.replication_token else b""
        encryption_key = hashlib.sha256(
            ("vault-guardian/totp/v1:" + self.replication_token).encode()
        ).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(encryption_key))

    @property
    def available(self) -> bool:
        return bool(self._session_key and self.configured)

    @property
    def configured(self) -> bool:
        return bool(self._read()["users"])

    def _blank(self) -> dict:
        return {"format": 1, "revision": 0, "users": []}

    def _validate_store(self, raw: object) -> dict:
        if (
            not isinstance(raw, dict)
            or type(raw.get("format")) is not int
            or raw.get("format") != 1
        ):
            raise SecurityError(
                "El estado de usuarios no es válido",
                "INVALID_SECURITY_STATE", 409)
        users = raw.get("users")
        if not isinstance(users, list) or len(users) > MAX_USERS:
            raise SecurityError(
                "El estado de usuarios no es válido",
                "INVALID_SECURITY_STATE", 409)
        revision = raw.get("revision", 0)
        if type(revision) is not int or not 0 <= revision <= MAX_SECURITY_REVISION:
            raise SecurityError(
                "La revisión del estado de usuarios no es válida",
                "INVALID_SECURITY_STATE", 409)
        normalized = {"format": 1, "revision": revision, "users": []}
        seen: set[str] = set()
        for raw_user in users:
            if not isinstance(raw_user, dict):
                raise SecurityError(
                    "El estado contiene un usuario no válido",
                    "INVALID_SECURITY_STATE", 409)
            user = copy.deepcopy(raw_user)
            try:
                username = normalize_username(user.get("username"))
            except SecurityError as exc:
                raise SecurityError(
                    "El estado contiene un usuario no válido",
                    "INVALID_SECURITY_STATE", 409) from exc
            session_version = user.get("session_version", 1)
            identifier = user.get("id")
            display_name = user.get("display_name", username)
            enabled = user.get("enabled", True)
            key = username.casefold()
            if (
                key in seen
                or _password_components(user.get("password_hash")) is None
                or type(session_version) is not int
                or not 1 <= session_version <= MAX_SECURITY_REVISION
                or not isinstance(identifier, str)
                or not 1 <= len(identifier) <= 128
                or any(ord(char) < 32 for char in identifier)
                or not isinstance(display_name, str)
                or not 1 <= len(display_name) <= 120
                or any(ord(char) < 32 for char in display_name)
                or not isinstance(enabled, bool)
            ):
                raise SecurityError(
                    "El estado contiene usuarios duplicados o incompletos",
                    "INVALID_SECURITY_STATE", 409)
            totp = user.get("totp")
            if totp is None:
                totp = {
                    "enabled": False, "secret": "", "pending_secret": "",  # nosec B105
                    "recovery_hashes": [],
                }
            recovery = totp.get("recovery_hashes") if isinstance(totp, dict) else None
            if (
                not isinstance(totp, dict)
                or not isinstance(totp.get("enabled", False), bool)
                or not isinstance(totp.get("secret", ""), str)
                or len(totp.get("secret", "")) > 4096
                or not isinstance(totp.get("pending_secret", ""), str)
                or len(totp.get("pending_secret", "")) > 4096
                or not isinstance(recovery, list)
                or len(recovery) > 100
                or any(
                    not isinstance(item, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", item)
                    for item in recovery
                )
            ):
                raise SecurityError(
                    "El estado contiene una configuración 2FA no válida",
                    "INVALID_SECURITY_STATE", 409)
            seen.add(key)
            user["username"] = username
            user["display_name"] = display_name
            user["enabled"] = enabled
            user["session_version"] = session_version
            user.setdefault("display_name", username)
            user["totp"] = totp
            normalized["users"].append(user)
        return normalized

    def _read(self) -> dict:
        with self._lock:
            if not self.path.exists():
                return self._blank()
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SecurityError(
                    f"No se puede leer el estado de usuarios: {exc}",
                    "SECURITY_STATE_UNAVAILABLE", 503) from exc
            return self._validate_store(raw)

    def _write(self, data: dict) -> None:
        validated = self._validate_store(data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.new")
        try:
            temporary.write_text(
                json.dumps(validated, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
            os.replace(temporary, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            temporary.unlink(missing_ok=True)


    def _find(self, data: dict, username: str) -> dict | None:
        key = str(username or "").strip().casefold()
        return next(
            (user for user in data["users"]
             if user["username"].casefold() == key),
            None,
        )

    def _public_user(self, user: dict) -> dict:
        totp = user.get("totp") or {}
        return {
            "id": user["id"],
            "username": user["username"],
            "display_name": user.get("display_name") or user["username"],
            "enabled": bool(user.get("enabled", True)),
            "two_factor_enabled": bool(totp.get("enabled")),
            "two_factor_pending": bool(totp.get("pending_secret")),
            "recovery_codes_remaining": len(totp.get("recovery_hashes") or []),
            "created_at": user.get("created_at"),
            "updated_at": user.get("updated_at"),
        }

    def status(self) -> dict:
        data = self._read()
        configured = bool(data["users"])
        return {
            "configured": configured,
            "available": bool(self._session_key),
            "setup_required": not configured,
            "user_count": len(data["users"]),
            "requires_replication_secret": not bool(self._session_key),
            "allow_insecure_portal": self.allow_insecure,
        }

    def setup_first_user(self, payload: dict) -> tuple[dict, dict, tuple[str, Identity]]:
        if not self._session_key:
            raise SecurityError(
                "Falta el secreto entre Guardian",
                "AUTH_NOT_CONFIGURED", 503)
        with self._lock:
            data = self._read()
            if data["users"]:
                raise SecurityError(
                    "La primera cuenta ya está configurada",
                    "AUTH_ALREADY_CONFIGURED", 409)
            # La comprobación de estado y el KDF forman una única sección crítica:
            # tras inicializar, una petición pública nunca debe consumir scrypt.
            username = normalize_username(payload.get("username"))
            password = str(payload.get("password") or "")
            confirmation = str(payload.get("password_confirmation") or "")
            if not hmac.compare_digest(password, confirmation):
                raise SecurityError(
                    "Las contraseñas no coinciden",
                    "PASSWORD_MISMATCH", 422)
            validate_password(password, username)
            display = " ".join(str(
                payload.get("display_name") or username).split())
            if not display or len(display) > 120:
                raise SecurityError(
                    "El nombre visible no es válido", "INVALID_USER", 422)
            allow_insecure = payload.get(
                "allow_insecure_portal", self.allow_insecure)
            if type(allow_insecure) is not bool:
                raise SecurityError(
                    "El tipo de acceso al portal no es valido",
                    "INVALID_PORTAL_ACCESS", 422)
            try:
                write_portal_access(self.path.parent, allow_insecure)
            except ValueError as exc:
                raise SecurityError(
                    str(exc), "INVALID_PORTAL_ACCESS", 409) from exc
            self.allow_insecure = allow_insecure
            now = int(time.time())
            user = {
                "id": str(uuid.uuid4()), "username": username,
                "display_name": display,
                "password_hash": hash_password(password),
                "enabled": True, "session_version": 1,
                "created_at": now, "updated_at": now,
                "totp": {
                    "enabled": False, "secret": "", "pending_secret": "",  # nosec B105
                    "recovery_hashes": [],
                },
            }
            data["users"].append(user)
            replication = self._save_mutation(data)
            return self._public_user(user), replication, self.create_session(user)

    def users(self) -> dict:
        data = self._read()
        return {
            "revision": data["revision"],
            "items": [self._public_user(user) for user in data["users"]],
        }

    def refresh_peers(self, peers: dict[str, str]) -> None:
        with self._lock:
            self._peers = dict(peers or {})

    def refresh_settings(self, settings) -> None:
        """Apply mutable portal settings without invalidating active sessions."""
        with self._lock:
            self._peers = dict(getattr(settings, "peers", {}) or {})
            self.session_minutes = max(
                5, min(480, int(getattr(settings, "session_minutes", 30))))
            self.allow_insecure = bool(
                getattr(settings, "allow_insecure_portal", False))
            self.allow_insecure_http = bool(
                getattr(settings, "allow_insecure_http", False))
            self.ca_file = getattr(settings, "ca_file", None)

    def replicate_current(self) -> dict:
        with self._lock:
            data = self._read()
            if not data["users"]:
                return {"updated": [], "failed": {}}
            return self._replicate(data)

    def _save_mutation(self, data: dict) -> dict:
        data["revision"] = int(data.get("revision") or 0) + 1
        self._write(data)
        return self._replicate(data)

    def _replicate(self, data: dict) -> dict:
        updated: list[str] = []
        failed: dict[str, str] = {}
        if not self.replication_token:
            return {"updated": updated, "failed": failed}
        payload = json.dumps(
            {"phase": "apply", "state": data},
            ensure_ascii=False, separators=(",", ":")).encode()
        for name, base_url in sorted(self._peers.items()):
            try:
                http_client.request(
                    base_url,
                    "/api/v1/internal/security",
                    method="PUT",
                    body=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Replication-Token": self.replication_token,
                    },
                    timeout=5,
                    max_bytes=64 * 1024,
                    allow_http=self.allow_insecure_http,
                    ca_file=self.ca_file,
                )
                updated.append(name)
            except http_client.HttpClientError as exc:
                failed[name] = str(exc)
        return {"updated": updated, "failed": failed}

    def apply_from_peer(self, payload: dict) -> dict:
        state = self._validate_store(payload.get("state"))
        phase = str(payload.get("phase") or "apply")
        if phase not in {"validate", "apply"}:
            raise SecurityError("Fase de seguridad no válida", "INVALID_PHASE", 422)
        with self._lock:
            current = self._read()
            if state["revision"] < current["revision"]:
                raise SecurityError(
                    "El estado de usuarios recibido es anterior al local",
                    "STALE_SECURITY_STATE", 409)
            if (
                state["revision"] == current["revision"]
                and state != current
            ):
                raise SecurityError(
                    "Existe otro estado de usuarios con la misma revisión",
                    "SECURITY_STATE_CONFLICT", 409)
            if phase == "apply" and state != current:
                self._write(state)
        return {
            "state": "validated" if phase == "validate" else "applied",
            "revision": state["revision"],
        }

    def _attempt_keys(self, origin: str, username: str) -> tuple[str, str]:
        origin_digest = hashlib.sha256(
            str(origin or "unknown").encode("utf-8", errors="replace")
        ).hexdigest()[:32]
        return (
            f"user:{username.casefold()}",
            f"origin:{origin_digest}",
        )

    def _prune_attempts(self, now: float, force: bool = False) -> None:
        if (
            not force
            and len(self._attempts) < ATTEMPT_KEY_LIMIT
            and now - self._last_attempt_prune < 5
        ):
            return
        for key, stamps in list(self._attempts.items()):
            active = [
                stamp for stamp in stamps
                if now - stamp < ATTEMPT_WINDOW_SECONDS
            ]
            if active:
                self._attempts[key] = active
            else:
                self._attempts.pop(key, None)
        self._last_attempt_prune = now

    def _active_attempts(self, key: str, now: float) -> list[float]:
        active = [
            stamp for stamp in self._attempts.get(key, [])
            if now - stamp < ATTEMPT_WINDOW_SECONDS
        ]
        if active:
            self._attempts[key] = active
        else:
            self._attempts.pop(key, None)
        return active

    def _check_rate(self, keys: tuple[str, str]) -> None:
        now = time.time()
        with self._lock:
            self._prune_attempts(now)
            limits = (ATTEMPT_LIMIT_PER_USER, ATTEMPT_LIMIT_PER_ORIGIN)
            for key, limit in zip(keys, limits):
                if len(self._active_attempts(key, now)) >= limit:
                    raise SecurityError(
                        "Demasiados intentos. Espera cinco minutos",
                        "LOGIN_RATE_LIMIT", 429)

    def _record_failure(self, keys: tuple[str, str]) -> None:
        now = time.time()
        with self._lock:
            self._prune_attempts(now)
            for key in keys:
                if key not in self._attempts:
                    if len(self._attempts) >= ATTEMPT_KEY_LIMIT:
                        self._prune_attempts(now, force=True)
                    if len(self._attempts) >= ATTEMPT_KEY_LIMIT:
                        oldest = min(
                            self._attempts,
                            key=lambda candidate: self._attempts[candidate][-1],
                        )
                        self._attempts.pop(oldest, None)
                self._attempts.setdefault(key, []).append(now)

    def _encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def _decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except (InvalidToken, ValueError) as exc:
            raise SecurityError(
                "No se puede descifrar la configuración 2FA",
                "TWO_FACTOR_STATE_INVALID", 503) from exc

    def _recovery_hash(self, code: object) -> str:
        normalized = re.sub(r"[^A-Za-z0-9]", "", str(code or "")).upper()
        key = hmac.new(
            self._session_key, b"vault-guardian/recovery/v1",
            hashlib.sha256).digest()
        return hmac.new(key, normalized.encode(), hashlib.sha256).hexdigest()

    def _verify_factor(self, user: dict, code: object) -> int | None | bool:
        totp = user.get("totp") or {}
        if not totp.get("enabled"):
            return None
        if verify_totp(self._decrypt(totp.get("secret") or ""), code):
            return True
        candidate = self._recovery_hash(code)
        for index, expected in enumerate(totp.get("recovery_hashes") or []):
            if hmac.compare_digest(candidate, expected):
                return index
        return False

    def login(self, username: object, password: object, second_factor: object,
              origin: str) -> tuple[str, Identity]:
        if not self._session_key:
            raise SecurityError(
                "Falta el secreto entre Guardian",
                "AUTH_NOT_CONFIGURED", 503)
        try:
            normalized = normalize_username(username)
        except SecurityError:
            normalized = ""
        keys = self._attempt_keys(origin, normalized or "<invalid>")
        with self._lock:
            # El límite se comprueba dentro de la misma sección que registra el
            # fallo y ejecuta scrypt: no hay ventana concurrente ni KDF paralelos.
            self._check_rate(keys)
            if not normalized:
                self._record_failure(keys)
                raise SecurityError("Usuario o contraseña no válidos")
            data = self._read()
            user = self._find(data, normalized)
            if (
                not user
                or not user.get("enabled", True)
                or not verify_password(str(password or ""), user["password_hash"])
            ):
                self._record_failure(keys)
                raise SecurityError("Usuario o contraseña no válidos")
            factor = self._verify_factor(user, second_factor)
            if factor is False:
                self._record_failure(keys)
                code = "TWO_FACTOR_REQUIRED" if not second_factor else "INVALID_SECOND_FACTOR"
                message = (
                    "Introduce el código de verificación"
                    if not second_factor
                    else "El código de verificación no es válido"
                )
                raise SecurityError(message, code, 401)
            if isinstance(factor, int) and not isinstance(factor, bool):
                user["totp"]["recovery_hashes"].pop(factor)
                user["updated_at"] = int(time.time())
                self._save_mutation(data)
            for key in keys:
                self._attempts.pop(key, None)
            return self.create_session(user)

    def create_session(self, user: dict) -> tuple[str, Identity]:
        now = int(time.time())
        body = {
            "sub": user["username"],
            "name": user.get("display_name") or user["username"],
            "sv": int(user.get("session_version") or 1),
            "csrf": secrets.token_urlsafe(24),
            "iat": now,
            "exp": now + self.session_minutes * 60,
            "nonce": secrets.token_hex(12),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(
            hmac.new(self._session_key, encoded.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        identity = Identity(
            body["sub"], body["name"], body["csrf"], body["exp"], body["sv"])
        return f"{encoded}.{signature}", identity

    def read_session(self, token: str) -> Identity | None:
        if not token or not self._session_key or "." not in token:
            return None
        encoded, signature = token.split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(self._session_key, encoded.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            body = json.loads(_decode_urlsafe(encoded).decode())
            identity = Identity(
                str(body["sub"]), str(body.get("name") or body["sub"]),
                str(body["csrf"]), int(body["exp"]), int(body.get("sv") or 1))
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            return None
        if identity.expires_at <= int(time.time()):
            return None
        user = self._find(self._read(), identity.username)
        if (
            not user
            or not user.get("enabled", True)
            or int(user.get("session_version") or 1) != identity.session_version
        ):
            return None
        return identity

    def public_session(self, identity: Identity) -> dict:
        user = self._find(self._read(), identity.username)
        if not user:
            raise SecurityError("La sesión ya no es válida")
        return {
            **self._public_user(user),
            "csrf_token": identity.csrf,
            "expires_at": identity.expires_at,
        }

    def add_user(self, payload: dict) -> tuple[dict, dict]:
        username = normalize_username(payload.get("username"))
        password = str(payload.get("password") or "")
        validate_password(password, username)
        display = " ".join(str(payload.get("display_name") or username).split())
        if not display or len(display) > 120:
            raise SecurityError("El nombre visible no es válido", "INVALID_USER", 422)
        with self._lock:
            data = self._read()
            if self._find(data, username):
                raise SecurityError("El usuario ya existe", "USER_EXISTS", 409)
            now = int(time.time())
            user = {
                "id": str(uuid.uuid4()), "username": username,
                "display_name": display, "password_hash": hash_password(password),
                "enabled": True, "session_version": 1,
                "created_at": now, "updated_at": now,
                "totp": {
                    "enabled": False, "secret": "", "pending_secret": "",  # nosec B105
                    "recovery_hashes": [],
                },
            }
            data["users"].append(user)
            replication = self._save_mutation(data)
            return self._public_user(user), replication

    def update_user(self, username: str, payload: dict) -> tuple[dict, dict]:
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            if not user:
                raise SecurityError("Usuario no encontrado", "USER_NOT_FOUND", 404)
            if "display_name" in payload:
                display = " ".join(str(payload.get("display_name") or "").split())
                if not display or len(display) > 120:
                    raise SecurityError(
                        "El nombre visible no es válido", "INVALID_USER", 422)
                user["display_name"] = display
            if payload.get("password"):
                password = str(payload["password"])
                validate_password(password, user["username"])
                user["password_hash"] = hash_password(password)
                user["session_version"] = int(user["session_version"]) + 1
            if "enabled" in payload:
                enabled = bool(payload["enabled"])
                if not enabled:
                    enabled_users = [item for item in data["users"]
                                     if item.get("enabled", True)]
                    if len(enabled_users) <= 1 and user.get("enabled", True):
                        raise SecurityError(
                            "Debe quedar al menos un usuario habilitado",
                            "LAST_USER", 409)
                    user["session_version"] = int(user["session_version"]) + 1
                user["enabled"] = enabled
            user["updated_at"] = int(time.time())
            replication = self._save_mutation(data)
            return self._public_user(user), replication

    def delete_user(self, username: str) -> dict:
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            if not user:
                raise SecurityError("Usuario no encontrado", "USER_NOT_FOUND", 404)
            if len(data["users"]) <= 1:
                raise SecurityError(
                    "Debe quedar al menos un usuario",
                    "LAST_USER", 409)
            data["users"].remove(user)
            return self._save_mutation(data)

    def update_profile(self, username: str, payload: dict) -> tuple[dict, dict, tuple[str, Identity]]:
        current_password = str(payload.get("current_password") or "")
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            if not user:
                raise SecurityError("Usuario no encontrado", "USER_NOT_FOUND", 404)
            if payload.get("new_password"):
                if not verify_password(current_password, user["password_hash"]):
                    raise SecurityError(
                        "La contraseña actual no es válida",
                        "INVALID_CURRENT_PASSWORD", 401)
                new_password = str(payload["new_password"])
                validate_password(new_password, user["username"])
                user["password_hash"] = hash_password(new_password)
                user["session_version"] = int(user["session_version"]) + 1
            if "display_name" in payload:
                display = " ".join(str(payload.get("display_name") or "").split())
                if not display or len(display) > 120:
                    raise SecurityError(
                        "El nombre visible no es válido", "INVALID_USER", 422)
                user["display_name"] = display
            user["updated_at"] = int(time.time())
            replication = self._save_mutation(data)
            return self._public_user(user), replication, self.create_session(user)

    def setup_totp(self, username: str) -> tuple[dict, dict]:
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            if not user:
                raise SecurityError("Usuario no encontrado", "USER_NOT_FOUND", 404)
            if (user.get("totp") or {}).get("enabled"):
                raise SecurityError("2FA ya está activo", "TWO_FACTOR_ENABLED", 409)
            user["totp"]["pending_secret"] = self._encrypt(secret)
            replication = self._save_mutation(data)
        issuer = "Vault Guardian"
        label = quote(f"{issuer}:{user['username']}", safe="")
        uri = "otpauth://totp/" + label + "?" + urlencode({
            "secret": secret, "issuer": issuer, "algorithm": "SHA1",
            "digits": 6, "period": 30,
        })
        qr_data = ""
        try:
            import qrcode
            from qrcode.image.svg import SvgPathFillImage
            image = qrcode.make(
                uri, image_factory=SvgPathFillImage, box_size=7, border=4)
            output = io.BytesIO()
            image.save(output)
            qr_data = (
                "data:image/svg+xml;base64,"
                + base64.b64encode(output.getvalue()).decode()
            )
        except ImportError:
            pass
        return {
            "secret": secret, "otpauth_uri": uri,
            "qr_data_url": qr_data, "issuer": issuer,
        }, replication

    def confirm_totp(self, username: str, code: object) -> tuple[list[str], dict, tuple[str, Identity]]:
        recovery_codes = []
        for _ in range(10):
            raw = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
            recovery_codes.append("-".join(raw[index:index + 4]
                                           for index in range(0, 16, 4)))
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            pending = ((user or {}).get("totp") or {}).get("pending_secret")
            if not user or not pending:
                raise SecurityError(
                    "No hay una configuración 2FA pendiente",
                    "TWO_FACTOR_SETUP_MISSING", 409)
            secret = self._decrypt(pending)
            if not verify_totp(secret, code):
                raise SecurityError(
                    "El código de verificación no es válido",
                    "INVALID_SECOND_FACTOR", 401)
            user["totp"] = {
                "enabled": True, "secret": pending, "pending_secret": "",  # nosec B105
                "recovery_hashes": [
                    self._recovery_hash(item) for item in recovery_codes
                ],
            }
            user["session_version"] = int(user["session_version"]) + 1
            user["updated_at"] = int(time.time())
            replication = self._save_mutation(data)
            return recovery_codes, replication, self.create_session(user)

    def disable_totp(self, username: str, code: object) -> tuple[dict, tuple[str, Identity]]:
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            if not user or not (user.get("totp") or {}).get("enabled"):
                raise SecurityError("2FA no está activo", "TWO_FACTOR_DISABLED", 409)
            if self._verify_factor(user, code) is False:
                raise SecurityError(
                    "El código de verificación no es válido",
                    "INVALID_SECOND_FACTOR", 401)
            user["totp"] = {
                "enabled": False, "secret": "", "pending_secret": "",  # nosec B105
                "recovery_hashes": [],
            }
            user["session_version"] = int(user["session_version"]) + 1
            user["updated_at"] = int(time.time())
            replication = self._save_mutation(data)
            return replication, self.create_session(user)

    def regenerate_recovery(self, username: str, code: object) -> tuple[list[str], dict]:
        with self._lock:
            data = self._read()
            user = self._find(data, username)
            if (
                not user
                or not (user.get("totp") or {}).get("enabled")
                or self._verify_factor(user, code) is False
            ):
                raise SecurityError(
                    "El código de verificación no es válido",
                    "INVALID_SECOND_FACTOR", 401)
            recovery_codes = []
            for _ in range(10):
                raw = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
                recovery_codes.append("-".join(
                    raw[index:index + 4] for index in range(0, 16, 4)))
            user["totp"]["recovery_hashes"] = [
                self._recovery_hash(item) for item in recovery_codes
            ]
            user["updated_at"] = int(time.time())
            replication = self._save_mutation(data)
            return recovery_codes, replication

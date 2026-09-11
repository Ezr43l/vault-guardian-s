"""Servidor HTTP de la API y el panel de Vault Guardian."""

from __future__ import annotations

import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import docker_api
from config import ConfigError, Settings
from replication import ReplicationError, ReplicationManager
from security import COOKIE_NAME, Identity, SecurityError, SecurityManager
from version import VERSION


STATIC_DIR = Path(os.getenv("VG_WEB_DIR", "/web")).resolve()
REQUEST_TIMEOUT_SECONDS = 15
STATIC_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class RequestBusyError(RuntimeError):
    """La capacidad acotada para cargas grandes está ocupada."""


class GuardianHandler(BaseHTTPRequestHandler):
    server_version = f"vault-guardian/{VERSION}"
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        self._large_body_acquired = False

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        finally:
            if self._large_body_acquired:
                self.server.large_body_slots.release()  # type: ignore[attr-defined]
                self._large_body_acquired = False

    @property
    def manager(self) -> ReplicationManager:
        return self.server.manager  # type: ignore[attr-defined]

    @property
    def security(self) -> SecurityManager:
        return self.server.security  # type: ignore[attr-defined]

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        )

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send_json(self, payload: dict, status: int = 200,
                   headers: dict[str, str] | None = None) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self._security_headers()
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Cache-Control",
            "no-store" if content_type.startswith(("text/html", "application/json"))
            else "public, max-age=3600",
        )
        if self.close_connection:
            self.send_header("Connection", "close")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status: int = 400,
               code: str = "REQUEST_ERROR") -> None:
        self.close_connection = True
        self._send_json({"error": message, "code": code}, status)

    def _security_error(self, error: SecurityError) -> None:
        self._error(str(error), error.status, error.code)

    def _static(self, path: str) -> None:
        relative = unquote(path)
        if relative in ("/", "/index.html"):
            relative = "/panel.html"
        destination = (STATIC_DIR / relative.lstrip("/")).resolve()
        if destination != STATIC_DIR and STATIC_DIR not in destination.parents:
            self._error("ruta no válida", 400)
            return
        if not destination.is_file():
            self._error("No existe", 404)
            return
        try:
            body = destination.read_bytes()
        except OSError:
            self._error("no se puede leer el recurso", 500)
            return
        self._send_bytes(body, STATIC_TYPES.get(destination.suffix.lower(),
                                               "application/octet-stream"))

    def _single_header(self, name: str) -> str:
        values = self.headers.get_all(name, [])
        if len(values) > 1:
            self.close_connection = True
            return ""
        return values[0] if values else ""

    def _authorized(self, internal: bool = False) -> bool:
        if internal:
            candidate = self._single_header("X-Replication-Token")
            expected = self.manager.settings.replication_token
            return bool(
                expected and candidate and hmac.compare_digest(candidate, expected))
        header = self._single_header("Authorization")
        candidate = (
            header.removeprefix("Bearer ").strip()
            if header.startswith("Bearer ") else ""
        )
        if not candidate:
            return False
        authenticate = getattr(
            self.manager, "authenticate_api_integration", None)
        if callable(authenticate) and authenticate(
            candidate, self.path.split("?", 1)[0]
        ):
            return True
        # Compatibilidad para dobles de prueba y estados anteriores a 1.0.15.
        expected = getattr(self.manager.settings, "api_token", "")
        return bool(expected and hmac.compare_digest(candidate, expected))

    def _session_token(self) -> str:
        raw = self._single_header("Cookie")
        if not raw:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:  # noqa: BLE001
            return ""
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else ""

    def _session_identity(self, mutation: bool = False) -> Identity | None:
        identity = self.security.read_session(self._session_token())
        if not identity:
            return None
        if mutation:
            candidate = self._single_header("X-CSRF-Token")
            if not candidate or not hmac.compare_digest(candidate, identity.csrf):
                return None
        return identity

    def _require_session(self, mutation: bool = False) -> Identity | None:
        identity = self._session_identity(mutation)
        if identity:
            return identity
        if mutation:
            self.close_connection = True
        self._error(
            "La sesión no es válida" if not mutation else "La verificación CSRF no es válida",
            401 if not mutation else 403,
            "SESSION_REQUIRED" if not mutation else "CSRF_INVALID",
        )
        return None

    def _cookie(self, token: str, max_age: int) -> str:
        parts = [
            f"{COOKIE_NAME}={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={max_age}",
        ]
        if not self.security.allow_insecure:
            parts.append("Secure")
        return "; ".join(parts)

    def _send_new_session(self, session: tuple[str, Identity],
                          payload: dict | None = None,
                          status: int = 200) -> None:
        token, identity = session
        response = dict(payload or {})
        response["session"] = self.security.public_session(identity)
        self._send_json(
            response,
            status,
            {"Set-Cookie": self._cookie(
                token, max(0, identity.expires_at - int(time.time())))},
        )

    def _content_length(self, maximum: int, required: bool, error_type) -> int:
        if self.headers.get_all("Transfer-Encoding", []):
            self.close_connection = True
            raise error_type("Transfer-Encoding no está permitido")
        values = self.headers.get_all("Content-Length", [])
        if not values:
            if not required:
                return 0
            self.close_connection = True
            raise error_type("falta Content-Length")
        if len(values) != 1:
            self.close_connection = True
            raise error_type("Content-Length duplicado")
        candidate = values[0].strip()
        if not re.fullmatch(r"[0-9]+", candidate):
            self.close_connection = True
            raise error_type("Content-Length no válido")
        length = int(candidate)
        if (required and length == 0) or length > maximum:
            self.close_connection = True
            raise error_type("tamaño de cuerpo no permitido")
        return length

    def _read_declared_body(self, length: int, error_type) -> bytes:
        try:
            body = self.rfile.read(length)
        except OSError as exc:
            self.close_connection = True
            raise error_type("no se pudo leer el cuerpo completo") from exc
        if len(body) != length:
            self.close_connection = True
            raise error_type("cuerpo incompleto")
        return body

    def _body(self) -> bytes:
        length = self._content_length(
            self.manager.settings.max_package_bytes, True, ReplicationError)
        if (
            not self._large_body_acquired
            and not self.server.large_body_slots.acquire(  # type: ignore[attr-defined]
                timeout=REQUEST_TIMEOUT_SECONDS
            )
        ):
            self.close_connection = True
            raise RequestBusyError(
                "ya hay una transferencia grande en curso; inténtalo de nuevo")
        self._large_body_acquired = True
        return self._read_declared_body(length, ReplicationError)

    def _read_json(self, maximum: int = 65536) -> dict:
        length = self._content_length(maximum, True, ConfigError)
        try:
            payload = json.loads(
                self._read_declared_body(length, ConfigError).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError("JSON inválido") from exc
        if not isinstance(payload, dict):
            raise ConfigError("el cuerpo JSON debe ser un objeto")
        return payload

    def _discard_body(self) -> None:
        length = self._content_length(65536, False, ConfigError)
        if not length:
            return
        self._read_declared_body(length, ConfigError)

    def _require_admin(self, *, allow_internal: bool = False) -> bool:
        read_only = self.command in {"GET", "HEAD", "OPTIONS"}
        if (
            self._authorized()
            or self._session_identity(mutation=not read_only)
            or (
                allow_internal
                and read_only
                and self._authorized(internal=True)
            )
        ):
            return True
        if self.command not in {"GET", "HEAD", "OPTIONS"}:
            self.close_connection = True
        self._error(
            "Se requiere una sesión válida o un token API",
            401, "AUTH_REQUIRED")
        return False

    def _require_internal(self) -> bool:
        if self._authorized(internal=True):
            return True
        self._error("token de replicación no válido", 401)
        return False

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/auth/status":
            try:
                self._send_json(self.security.status())
            except SecurityError as exc:
                self._security_error(exc)
            return
        if path == "/api/v1/session":
            identity = self._require_session()
            if identity:
                try:
                    self._send_json(self.security.public_session(identity))
                except SecurityError as exc:
                    self._security_error(exc)
            return
        if path == "/api/v1/users":
            if not self._require_session():
                return
            try:
                self._send_json(self.security.users())
            except SecurityError as exc:
                self._security_error(exc)
            return
        if path in ("/metrics", "/api/v1/metrics"):
            if not self._require_admin():
                return
            self._send_bytes(
                self.manager.metrics().encode("utf-8"),
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return
        if path == "/api/health":
            self._send_json({
                "estado": "ok",
                "nodo": self.manager.settings.node,
                "modo": self.manager.settings.mode,
                "configurado": bool(self.manager.settings.instances),
                "version": VERSION,
            })
            return
        if path == "/api/version":
            self._send_json({"version": VERSION})
            return
        if path == "/api/v1/status":
            if not self._require_admin(allow_internal=True):
                return
            self._send_json(self.manager.status())
            return
        if path == "/api/status":
            if not self._require_admin():
                return
            self._send_json(self.manager.status())
            return
        if path == "/api/v1/cluster":
            if not self._require_admin():
                return
            self._send_json(self.manager.cluster_status())
            return
        if path == "/api/v1/history":
            if not self._require_admin():
                return
            query = parse_qs(urlsplit(self.path).query)
            try:
                limit = int((query.get("limit") or ["100"])[0])
            except ValueError:
                self._error("limit no válido", 400)
                return
            try:
                payload = self.manager.history(limit)
            except ReplicationError as exc:
                self._error(str(exc), 500, "STATE_UNAVAILABLE")
            else:
                self._send_json(payload)
            return
        if path == "/api/v1/integrations/applications":
            if not self._require_session():
                return
            try:
                self._send_json(self.manager.list_api_integrations())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            return
        integration_token_match = re.fullmatch(
            r"/api/v1/integrations/applications/"
            r"(app_[a-f0-9]{24}|legacy_api_token)/token",
            path,
        )
        if integration_token_match:
            if not self._require_session():
                return
            try:
                self._send_json(self.manager.reveal_api_application(
                    integration_token_match.group(1)))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 404)
            return
        if path in ("/api/v1/config", "/api/config"):
            if not self._require_admin():
                return
            self._send_json(self.manager.config())
            return
        if path == "/api/v1/setup":
            if not self._require_admin():
                return
            self._send_json(self.manager.setup_status())
            return
        if path == "/api/v1/cluster/enrollment-token":
            if not self._require_admin():
                return
            try:
                token = self.manager.enrollment_token()
            except ConfigError as exc:
                self._error(str(exc), 409)
            else:
                self._send_json({"token": token})
            return
        if path in ("/api/v1/discovery", "/api/discovery"):
            if not self._require_admin():
                return
            self._send_json(self.manager.discovery())
            return
        if path == "/api/v1/provisioning/candidates":
            if not self._require_admin():
                return
            try:
                result = self.manager.provisioning_candidates()
            except (ReplicationError, ConfigError, docker_api.DockerError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(
            r"/api/v1/provisioning/transactions/"
            r"([A-Za-z0-9][A-Za-z0-9._:-]{7,127})",
            path,
        )
        if match:
            if not self._require_admin():
                return
            try:
                result = self.manager.provisioning_transaction(match.group(1))
            except ReplicationError as exc:
                self._error(str(exc), 404)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/admin":
            if not self._require_admin():
                return
            self._send_json({"autorizado": True})
            return
        if path in ("/api/v1/instances", "/api/instances"):
            if not self._require_admin():
                return
            self._send_json({"items": self.manager.status()["instancias"]})
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)/readiness", path)
        if match:
            try:
                result = self.manager.instance_readiness(match.group(1))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result, 200 if result["ready"] else 503)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)/backups", path)
        if match:
            if not self._require_admin():
                return
            try:
                result = self.manager.backups(match.group(1))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)", path)
        if match:
            if not self._require_admin():
                return
            identifier = match.group(1)
            try:
                item = next(x for x in self.manager.status()["instancias"] if x["id"] == identifier)
            except StopIteration:
                self._error("instancia no encontrada", 404)
            else:
                self._send_json(item)
            return
        if path.startswith("/api/"):
            self._error("No existe", 404)
            return
        self._static(path)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/auth/setup":
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ConfigError("el alta requiere un objeto JSON")
                cluster_token = str(payload.pop("cluster_token", "") or "").strip()
                if cluster_token:
                    self.manager.configure_enrollment_token(cluster_token)
                    self.server.security = SecurityManager(  # type: ignore[attr-defined]
                        self.manager.settings)
                user, replication, session = self.security.setup_first_user(payload)
                self._send_new_session(
                    session,
                    {
                        "configured": True,
                        "user": user,
                        "replication": replication,
                    },
                    201,
                )
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/session":
            try:
                payload = self._read_json()
                session = self.security.login(
                    payload.get("username"),
                    payload.get("password"),
                    payload.get("second_factor"),
                    self.client_address[0],
                )
                self._send_new_session(session, {"authenticated": True})
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/users":
            if not self._require_session(mutation=True):
                return
            try:
                user, replication = self.security.add_user(self._read_json())
                self._send_json(
                    {"user": user, "replication": replication}, 201)
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/profile/2fa/setup":
            identity = self._require_session(mutation=True)
            if not identity:
                return
            try:
                self._discard_body()
                setup, replication = self.security.setup_totp(identity.username)
                self._send_json({"setup": setup, "replication": replication})
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/profile/2fa/confirm":
            identity = self._require_session(mutation=True)
            if not identity:
                return
            try:
                codes, replication, session = self.security.confirm_totp(
                    identity.username, self._read_json().get("code"))
                self._send_new_session(
                    session,
                    {"recovery_codes": codes, "replication": replication},
                )
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/profile/2fa/disable":
            identity = self._require_session(mutation=True)
            if not identity:
                return
            try:
                replication, session = self.security.disable_totp(
                    identity.username, self._read_json().get("code"))
                self._send_new_session(
                    session, {"disabled": True, "replication": replication})
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/profile/recovery-codes":
            identity = self._require_session(mutation=True)
            if not identity:
                return
            try:
                codes, replication = self.security.regenerate_recovery(
                    identity.username, self._read_json().get("code"))
                self._send_json({
                    "recovery_codes": codes, "replication": replication})
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/reconciliation":
            if not self._require_admin():
                return
            try:
                result = self.manager.reconcile_cluster(self._read_json())
            except (ReplicationError, ConfigError, docker_api.DockerError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/integrations/applications":
            if not self._require_session(mutation=True):
                return
            try:
                result = self.manager.create_api_integration(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result, 201)
            return
        integration_rotate_match = re.fullmatch(
            r"/api/v1/integrations/applications/"
            r"(app_[a-f0-9]{24}|legacy_api_token)/rotate",
            path,
        )
        if integration_rotate_match:
            if not self._require_session(mutation=True):
                return
            try:
                result = self.manager.rotate_api_application(
                    integration_rotate_match.group(1), self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/internal/reconciliation":
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_reconcile_instance(
                    self._read_json())
            except (ReplicationError, ConfigError, docker_api.DockerError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/provisioning":
            if not self._require_admin():
                return
            transaction = self.headers.get("Idempotency-Key", "").strip()
            try:
                result = self.manager.provision_vaultwarden(
                    self._read_json(), transaction)
            except (ReplicationError, ConfigError, docker_api.DockerError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result, 201)
            return
        if path == "/api/v1/internal/provisioning/preflight":
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_provisioning_preflight(
                    self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/internal/provisioning/prepare":
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_provisioning_prepare(
                    self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result, 201)
            return
        match = re.fullmatch(
            r"/api/v1/internal/provisioning/"
            r"([A-Za-z0-9][A-Za-z0-9._:-]{7,127})/snapshot",
            path,
        )
        if match:
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_provisioning_snapshot(
                    match.group(1), self._body())
            except RequestBusyError as exc:
                self._error(str(exc), 503, "SERVER_BUSY")
            except (ReplicationError, ValueError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(
            r"/api/v1/internal/provisioning/"
            r"([A-Za-z0-9][A-Za-z0-9._:-]{7,127})/activate",
            path,
        )
        if match:
            if not self._require_internal():
                return
            try:
                self._discard_body()
                result = self.manager.internal_provisioning_activate(
                    match.group(1))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/instances/validate":
            if not self._require_admin():
                return
            try:
                result = self.manager.validate_instance(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/instances":
            if not self._require_admin():
                return
            try:
                result = self.manager.upsert_instance_cluster(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result, 201)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)/restore", path)
        if match:
            if not self._require_admin():
                return
            try:
                body = self._read_json()
                result = self.manager.restore(
                    match.group(1),
                    body.get("backup"),
                    body.get("confirm") is True,
                )
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)/baseline", path)
        if match:
            if not self._require_admin():
                return
            try:
                body = self._read_json()
                result = self.manager.baseline(
                    match.group(1),
                    body.get("expected_fingerprint"),
                    body.get("confirm") is True,
                )
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)/sync", path)
        if match:
            if not self._require_admin():
                return
            try:
                self._discard_body()
            except ConfigError as exc:
                self._error(str(exc), 400)
                return
            try:
                result = self.manager.sync_selected(match.group(1))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(r"/api/v1/internal/sync/([A-Za-z0-9_.-]+)", path)
        if match:
            if not self._require_internal():
                return
            try:
                body = self._read_json()
                source = str(body.get("solicitado_desde", "")).strip()
                context = {
                    "instance": match.group(1),
                    "ejecutado_por": self.manager.settings.node,
                }
                if source:
                    context["solicitado_desde"] = source
                result = self.manager.sync(match.group(1), context=context)
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        match = re.fullmatch(r"/api/v1/internal/replication/([A-Za-z0-9_.-]+)", path)
        if match:
            if not self._require_internal():
                return
            try:
                result = self.manager.receive(match.group(1), self._body(),
                                              self._single_header("X-VG-Source-Node"))
            except RequestBusyError as exc:
                self._error(str(exc), 503, "SERVER_BUSY")
            except (ReplicationError, ValueError) as exc:
                self._error(str(exc), 409)
            except Exception as exc:  # noqa: BLE001 - nunca ocultar un reinicio fallido
                self._error(f"fallo interno: {type(exc).__name__}", 500)
            else:
                self._send_json(result)
            return
        self._error("No existe", 404)

    def do_PUT(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        integration_match = re.fullmatch(
            r"/api/v1/integrations/applications/"
            r"(app_[a-f0-9]{24}|legacy_api_token)",
            path,
        )
        if integration_match:
            if not self._require_session(mutation=True):
                return
            try:
                result = self.manager.update_api_application(
                    integration_match.group(1), self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/internal/security":
            if not self._require_internal():
                return
            try:
                self._send_json(
                    self.security.apply_from_peer(self._read_json()))
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/profile":
            identity = self._require_session(mutation=True)
            if not identity:
                return
            try:
                user, replication, session = self.security.update_profile(
                    identity.username, self._read_json())
                self._send_new_session(
                    session, {"user": user, "replication": replication})
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        user_match = re.fullmatch(
            r"/api/v1/users/([A-Za-z0-9][A-Za-z0-9._@+-]{2,63})",
            path,
        )
        if user_match:
            identity = self._require_session(mutation=True)
            if not identity:
                return
            try:
                payload = self._read_json()
                if (
                    identity.username.casefold() == user_match.group(1).casefold()
                    and ("password" in payload or "enabled" in payload)
                ):
                    raise SecurityError(
                        "Usa Mi cuenta para cambiar tus credenciales",
                        "CURRENT_USER", 409)
                user, replication = self.security.update_user(
                    user_match.group(1), payload)
                self._send_json({"user": user, "replication": replication})
            except (SecurityError, ConfigError) as exc:
                if isinstance(exc, SecurityError):
                    self._security_error(exc)
                else:
                    self._error(str(exc), 400)
            return
        if path == "/api/v1/cluster/policy":
            if not self._require_admin():
                return
            try:
                result = self.manager.update_cluster_policy(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_peers(self.manager.settings.peers)
                self._send_json(result)
            return
        if path == "/api/v1/cluster/configuration":
            if not self._require_admin():
                return
            try:
                result = self.manager.configure_cluster(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_peers(self.manager.settings.peers)
                result["identidades"] = self.security.replicate_current()
                self._send_json(result)
            return
        if path == "/api/v1/internal/policy":
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_policy(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_peers(self.manager.settings.peers)
                self._send_json(result)
            return
        if path == "/api/v1/internal/settings":
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_settings(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_peers(self.manager.settings.peers)
                self._send_json(result)
            return
        if path == "/api/v1/internal/instance-config":
            if not self._require_internal():
                return
            try:
                result = self.manager.internal_instance_config(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/settings":
            if not self._require_admin():
                return
            try:
                result = self.manager.update_settings(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_peers(self.manager.settings.peers)
                self._send_json(result)
            return
        if path == "/api/v1/integrations/keepalived":
            if not self._require_admin():
                return
            try:
                result = self.manager.update_keepalived_integration(
                    self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/application-settings":
            if not self._require_admin():
                return
            try:
                result = self.manager.update_application_settings(
                    self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_settings(self.manager.settings)
                self._send_json(result)
            return
        if path == "/api/v1/integrations/api-token":
            if not self._require_admin():
                return
            try:
                result = self.manager.update_api_integration(self._read_json())
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/tls/private-ca":
            if not self._require_admin():
                return
            try:
                result = self.manager.update_private_ca(
                    self._read_json(4 * 1024 * 1024 + 65536))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_settings(self.manager.settings)
                self._send_json(result)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)", path)
        if not match:
            self._error("No existe", 404)
            return
        if not self._require_admin():
            return
        try:
            result = self.manager.upsert_instance_cluster(self._read_json(), match.group(1))
        except (ReplicationError, ConfigError) as exc:
            self._error(str(exc), 409)
        else:
            self._send_json(result)

    def do_DELETE(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/session":
            self._send_json(
                {"authenticated": False},
                headers={"Set-Cookie": self._cookie("", 0)},
            )
            return
        integration_match = re.fullmatch(
            r"/api/v1/integrations/applications/"
            r"(app_[a-f0-9]{24}|legacy_api_token)",
            path,
        )
        if integration_match:
            if not self._require_session(mutation=True):
                return
            try:
                result = self.manager.delete_api_application(
                    integration_match.group(1))
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/integrations/api-token":
            if not self._require_admin():
                return
            try:
                result = self.manager.disable_api_integration()
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self._send_json(result)
            return
        if path == "/api/v1/tls/private-ca":
            if not self._require_admin():
                return
            try:
                result = self.manager.disable_private_ca()
            except (ReplicationError, ConfigError) as exc:
                self._error(str(exc), 409)
            else:
                self.security.refresh_settings(self.manager.settings)
                self._send_json(result)
            return
        user_match = re.fullmatch(
            r"/api/v1/users/([A-Za-z0-9][A-Za-z0-9._@+-]{2,63})",
            path,
        )
        if user_match:
            identity = self._require_session(mutation=True)
            if not identity:
                return
            if identity.username.casefold() == user_match.group(1).casefold():
                self._error(
                    "No puedes eliminar la cuenta de la sesión actual",
                    409, "CURRENT_USER")
                return
            try:
                replication = self.security.delete_user(user_match.group(1))
                self._send_json({
                    "deleted": user_match.group(1),
                    "replication": replication,
                })
            except SecurityError as exc:
                self._security_error(exc)
            return
        match = re.fullmatch(r"/api/v1/instances/([A-Za-z0-9_.-]+)", path)
        if not match:
            self._error("No existe", 404)
            return
        if not self._require_admin():
            return
        try:
            result = self.manager.delete_instance_cluster(match.group(1))
        except (ReplicationError, ConfigError) as exc:
            self._error(str(exc), 409)
        else:
            self._send_json(result)


class GuardianServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address, manager, security=None):
        self.request_slots = threading.BoundedSemaphore(32)
        self.large_body_slots = threading.BoundedSemaphore(1)
        super().__init__(address, GuardianHandler)
        self.manager = manager
        self.security = security or SecurityManager(manager.settings)

    def process_request(self, request, client_address) -> None:
        if not self.request_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


def _ensure_instances_file(filename: str) -> None:
    path = Path(filename)
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.new")
    temporary.write_text(json.dumps({"format": 1, "instances": []}, indent=2) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)


def _worker(manager: ReplicationManager) -> None:
    while True:
        if manager.settings.mode == "active":
            for instance in manager.settings.instances:
                try:
                    manager.sync(instance.id)
                except Exception as exc:  # noqa: BLE001 - el siguiente ciclo reintenta
                    manager._remember(instance.id, {"estado": "error", "motivo": str(exc)})
        time.sleep(manager.settings.interval_seconds)


def main() -> None:
    filename = os.environ.get("VG_INSTANCES_FILE", "/state/instances.json")
    _ensure_instances_file(filename)
    settings = Settings.load(filename)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    manager = ReplicationManager(settings)
    threading.Thread(target=_worker, args=(manager,), daemon=True, name="replicador").start()
    print(f"vault-guardian · nodo={settings.node} modo={settings.mode} instancias={len(settings.instances)}",
          flush=True)
    # Dentro del contenedor; la publicación y el firewall pertenecen al despliegue.
    GuardianServer(("0.0.0.0", int(os.environ.get("VG_PORT", "6062"))), manager).serve_forever()  # nosec B104


if __name__ == "__main__":
    main()

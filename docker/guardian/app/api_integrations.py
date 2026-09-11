"""Registro local de aplicaciones autorizadas para consumir la API."""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path


class ApiIntegrationError(ValueError):
    """Una integración no es válida o no puede persistirse."""


_IDENTIFIER = re.compile(r"^app_[a-f0-9]{24}$|^legacy_api_token$")
_TOKEN_MIN = 32
_TOKEN_MAX = 4096
_MAX_APPLICATIONS = 100
_MAX_FILE_BYTES = 1024 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _name(value: object) -> str:
    normalized = " ".join(str(value or "").strip().split())
    if not 2 <= len(normalized) <= 80 or any(
        ord(character) < 32 for character in normalized
    ):
        raise ApiIntegrationError(
            "el nombre de la aplicación debe tener entre 2 y 80 caracteres")
    return normalized


def _token(value: object) -> str:
    normalized = str(value or "").strip()
    if (
        not _TOKEN_MIN <= len(normalized) <= _TOKEN_MAX
        or any(not 33 <= ord(character) <= 126 for character in normalized)
    ):
        raise ApiIntegrationError(
            "el token debe tener entre 32 y 4096 caracteres ASCII imprimibles")
    return normalized


def _timestamp(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value in (None, ""):
        return None
    raw = str(value or "")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiIntegrationError(f"{label} no contiene una fecha válida") from exc
    if parsed.tzinfo is None:
        raise ApiIntegrationError(f"{label} debe incluir zona horaria")
    return parsed.isoformat(timespec="seconds")


class ApiIntegrationStore:
    """Persiste tokens por aplicación y registra qué credencial usa la API."""

    def __init__(self, state_dir: str | Path):
        self.directory = Path(state_dir) / "secrets"
        self.path = self.directory / "api-integrations.json"
        self._lock = threading.RLock()

    @staticmethod
    def generate_token() -> str:
        return "vg_api_" + secrets.token_urlsafe(48)

    @staticmethod
    def _normalize_record(raw: object) -> dict:
        if not isinstance(raw, dict):
            raise ApiIntegrationError("cada integración debe ser un objeto")
        allowed = {
            "id", "name", "token", "created_at", "updated_at",
            "last_used_at", "last_endpoint", "usage_count", "legacy",
        }
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ApiIntegrationError(
                "campos de integración no permitidos: " + ", ".join(unknown))
        identifier = str(raw.get("id") or "")
        if not _IDENTIFIER.fullmatch(identifier):
            raise ApiIntegrationError("el identificador de integración no es válido")
        endpoint = str(raw.get("last_endpoint") or "")
        if len(endpoint) > 256 or any(ord(character) < 32 for character in endpoint):
            raise ApiIntegrationError("la última ruta de integración no es válida")
        try:
            usage_count = int(raw.get("usage_count", 0))
        except (TypeError, ValueError) as exc:
            raise ApiIntegrationError("el contador de uso no es válido") from exc
        if not 0 <= usage_count <= 2**63 - 1:
            raise ApiIntegrationError("el contador de uso no es válido")
        if type(raw.get("legacy", False)) is not bool:
            raise ApiIntegrationError("legacy debe ser true o false")
        return {
            "id": identifier,
            "name": _name(raw.get("name")),
            "token": _token(raw.get("token")),
            "created_at": _timestamp(raw.get("created_at"), "created_at"),
            "updated_at": _timestamp(raw.get("updated_at"), "updated_at"),
            "last_used_at": _timestamp(
                raw.get("last_used_at"), "last_used_at", optional=True),
            "last_endpoint": endpoint,
            "usage_count": usage_count,
            "legacy": raw.get("legacy", False),
        }

    def _read(self) -> list[dict]:
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ApiIntegrationError(
                "no se puede inspeccionar el registro de integraciones") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_FILE_BYTES
        ):
            raise ApiIntegrationError(
                "el registro de integraciones no es un fichero regular y acotado")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiIntegrationError(
                "no se puede leer el registro de integraciones") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("format") != 1
            or not isinstance(payload.get("applications"), list)
        ):
            raise ApiIntegrationError(
                "el registro de integraciones requiere format=1")
        records = [self._normalize_record(item) for item in payload["applications"]]
        if len(records) > _MAX_APPLICATIONS:
            raise ApiIntegrationError("hay demasiadas integraciones configuradas")
        identifiers = [item["id"] for item in records]
        tokens = [item["token"] for item in records]
        if len(identifiers) != len(set(identifiers)) or len(tokens) != len(set(tokens)):
            raise ApiIntegrationError("hay integraciones o tokens duplicados")
        return records

    def _write(self, records: list[dict]) -> None:
        normalized = [self._normalize_record(item) for item in records]
        if len(normalized) > _MAX_APPLICATIONS:
            raise ApiIntegrationError("hay demasiadas integraciones configuradas")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.directory / f".{self.path.name}.{os.getpid()}.new"
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(
                    {"format": 1, "applications": normalized},
                    target,
                    ensure_ascii=False,
                    indent=2,
                )
                target.write("\n")
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _public(record: dict) -> dict:
        token = record["token"]
        return {
            "id": record["id"],
            "name": record["name"],
            "token_hint": token[:10] + "…" + token[-4:],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "last_used_at": record["last_used_at"],
            "last_endpoint": record["last_endpoint"] or None,
            "usage_count": record["usage_count"],
            "legacy": record["legacy"],
        }

    def import_legacy(self, value: str) -> None:
        """Representa el antiguo token único sin cambiar su valor ni romperlo."""
        if not value:
            return
        token = _token(value)
        with self._lock:
            records = self._read()
            if any(hmac.compare_digest(item["token"], token) for item in records):
                return
            legacy = next(
                (item for item in records if item["id"] == "legacy_api_token"),
                None,
            )
            if legacy is not None:
                legacy["token"] = token
                legacy["updated_at"] = _now()
                self._write(records)
                return
            if len(records) >= _MAX_APPLICATIONS:
                raise ApiIntegrationError("hay demasiadas integraciones configuradas")
            now = _now()
            records.append({
                "id": "legacy_api_token",
                "name": "Integración anterior sin identificar",
                "token": token,
                "created_at": now,
                "updated_at": now,
                "last_used_at": None,
                "last_endpoint": "",
                "usage_count": 0,
                "legacy": True,
            })
            self._write(records)

    def list(self) -> list[dict]:
        with self._lock:
            return [self._public(item) for item in self._read()]

    def create(self, name: object, value: object = "") -> tuple[dict, str]:
        with self._lock:
            records = self._read()
            if len(records) >= _MAX_APPLICATIONS:
                raise ApiIntegrationError("hay demasiadas integraciones configuradas")
            token = _token(value) if str(value or "").strip() else self.generate_token()
            if any(hmac.compare_digest(item["token"], token) for item in records):
                raise ApiIntegrationError("el token ya pertenece a otra aplicación")
            now = _now()
            record = {
                "id": "app_" + secrets.token_hex(12),
                "name": _name(name),
                "token": token,
                "created_at": now,
                "updated_at": now,
                "last_used_at": None,
                "last_endpoint": "",
                "usage_count": 0,
                "legacy": False,
            }
            records.append(record)
            self._write(records)
            return self._public(record), token

    def update(self, identifier: str, *, name: object | None = None,
               token: object | None = None) -> tuple[dict, str | None]:
        with self._lock:
            records = self._read()
            record = next((item for item in records if item["id"] == identifier), None)
            if record is None:
                raise ApiIntegrationError("la aplicación no existe")
            replacement = None
            if name is not None:
                record["name"] = _name(name)
            if token is not None:
                replacement = _token(token) if str(token or "").strip() else self.generate_token()
                if any(
                    item["id"] != identifier
                    and hmac.compare_digest(item["token"], replacement)
                    for item in records
                ):
                    raise ApiIntegrationError("el token ya pertenece a otra aplicación")
                record["token"] = replacement
            record["updated_at"] = _now()
            self._write(records)
            return self._public(record), replacement

    def reveal(self, identifier: str) -> str:
        with self._lock:
            record = next(
                (item for item in self._read() if item["id"] == identifier), None)
            if record is None:
                raise ApiIntegrationError("la aplicación no existe")
            return record["token"]

    def delete(self, identifier: str) -> dict:
        with self._lock:
            records = self._read()
            record = next((item for item in records if item["id"] == identifier), None)
            if record is None:
                raise ApiIntegrationError("la aplicación no existe")
            self._write([item for item in records if item["id"] != identifier])
            return self._public(record)

    def authenticate(self, candidate: str, endpoint: str = "") -> dict | None:
        if not candidate:
            return None
        with self._lock:
            records = self._read()
            matched = next(
                (item for item in records
                 if hmac.compare_digest(item["token"], candidate)),
                None,
            )
            if matched is None:
                return None
            matched["last_used_at"] = _now()
            matched["last_endpoint"] = str(endpoint or "")[:256]
            matched["usage_count"] += 1
            self._write(records)
            return self._public(matched)

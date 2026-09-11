"""Configuración declarativa y validada del guardián."""

from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path

import http_client
import runtime_config


class ConfigError(ValueError):
    """La configuración no es segura o no se puede interpretar."""


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_MAX_SECRET_BYTES = 16 * 1024
_MAX_CA_BYTES = 4 * 1024 * 1024
_DEFAULT_HISTORY_MAX_MB = 16
_DEFAULT_HISTORY_MAX_ENTRIES = 5_000
_PORTAL_ACCESS_FILE = "portal-access.json"
_LOCAL_SETTINGS_FILE = "application-settings.json"
_MANAGED_CA_FILE = "private-ca.pem"
_DISABLED_SUFFIX = ".disabled"


def _boolean(name: str, default: bool = False) -> bool:
    value = os.getenv(name, "true" if default else "false").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} debe ser true o false")


def _secret(name: str) -> str:
    direct = os.getenv(name, "").strip()
    file_name = os.getenv(f"{name}_FILE", "").strip()
    if direct and file_name:
        raise ConfigError(f"usa {name} o {name}_FILE, no ambos")
    if not file_name:
        return direct
    path = Path(file_name)
    if not path.is_absolute():
        raise ConfigError(f"{name}_FILE debe ser una ruta absoluta")
    try:
        metadata = path.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > _MAX_SECRET_BYTES):
            raise ConfigError(f"{name}_FILE debe ser un fichero regular y acotado")
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"no se puede leer {name}_FILE") from exc
    if "\n" in value or "\r" in value:
        raise ConfigError(f"{name}_FILE debe contener un único secreto")
    return value


def _token(name: str) -> str:
    value = _secret(name)
    return _validate_token(name, value)


def _validate_token(name: str, value: str) -> str:
    if value and (
        not 32 <= len(value) <= 4096
        or any(not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ConfigError(
            f"{name} debe estar vacío o tener entre 32 y 4096 caracteres ASCII imprimibles"
        )
    return value


def _portal_access(state_dir: Path) -> bool:
    """Read the editable portal transport choice, with env as migration fallback."""
    path = state_dir / _PORTAL_ACCESS_FILE
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ConfigError(f"{path} debe ser un fichero regular")
        if metadata.st_size > 4096:
            raise ConfigError(f"{path} es demasiado grande")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if os.getenv("VG_ALLOW_INSECURE_PORTAL", "").strip():
            return _boolean("VG_ALLOW_INSECURE_PORTAL")
        return False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"no se puede leer {path}") from exc
    if (not isinstance(payload, dict) or set(payload) != {"format", "allow_insecure"}
            or payload.get("format") != 1
            or type(payload.get("allow_insecure")) is not bool):
        raise ConfigError(f"{path} no contiene una configuracion valida")
    return payload["allow_insecure"]


def write_portal_access(state_dir: Path, allow_insecure: bool) -> bool:
    """Persist the editable HTTP/HTTPS choice without exposing it in Docker."""
    if type(allow_insecure) is not bool:
        raise ConfigError("allow_insecure_portal debe ser true o false")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = state_dir / _PORTAL_ACCESS_FILE
    temporary = state_dir / f".{_PORTAL_ACCESS_FILE}.{os.getpid()}.new"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump({"format": 1, "allow_insecure": allow_insecure}, target)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)
    return allow_insecure


def _normalize_local_settings(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ConfigError("los ajustes locales deben ser un objeto")
    allowed = {"session_minutes", "history_max_mb", "history_max_entries"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ConfigError("ajustes locales no permitidos: " + ", ".join(unknown))
    try:
        session_minutes = int(raw.get("session_minutes", 30))
        history_max_mb = int(raw.get("history_max_mb", _DEFAULT_HISTORY_MAX_MB))
        history_max_entries = int(raw.get(
            "history_max_entries", _DEFAULT_HISTORY_MAX_ENTRIES))
    except (TypeError, ValueError) as exc:
        raise ConfigError("sesion e historial deben usar numeros enteros") from exc
    if not 5 <= session_minutes <= 480:
        raise ConfigError("session_minutes debe estar entre 5 y 480")
    if not 1 <= history_max_mb <= 256:
        raise ConfigError("history_max_mb debe estar entre 1 y 256")
    if not 500 <= history_max_entries <= 100_000:
        raise ConfigError("history_max_entries debe estar entre 500 y 100000")
    return {
        "session_minutes": session_minutes,
        "history_max_mb": history_max_mb,
        "history_max_entries": history_max_entries,
    }


def _local_settings(state_dir: Path) -> dict:
    """Load portal-local values, using old environment values only as fallback."""
    path = state_dir / _LOCAL_SETTINGS_FILE
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ConfigError(f"{path} debe ser un fichero regular")
        if metadata.st_size > 16 * 1024:
            raise ConfigError(f"{path} es demasiado grande")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _normalize_local_settings({
            "session_minutes": os.getenv("VG_SESSION_MINUTES", "30"),
            "history_max_mb": os.getenv(
                "VG_HISTORY_MAX_MB", str(_DEFAULT_HISTORY_MAX_MB)),
            "history_max_entries": os.getenv(
                "VG_HISTORY_MAX_ENTRIES", str(_DEFAULT_HISTORY_MAX_ENTRIES)),
        })
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"no se puede leer {path}") from exc
    if not isinstance(payload, dict) or payload.get("format") != 1:
        raise ConfigError(f"{path} requiere format=1")
    return _normalize_local_settings({
        key: value for key, value in payload.items() if key != "format"
    })


def write_local_settings(state_dir: Path, raw: dict) -> dict:
    """Persist editable portal and history limits atomically."""
    normalized = _normalize_local_settings(raw)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = state_dir / _LOCAL_SETTINGS_FILE
    temporary = state_dir / f".{_LOCAL_SETTINGS_FILE}.{os.getpid()}.new"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump({"format": 1, **normalized}, target, ensure_ascii=False, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)
    return normalized


def _managed_token(path: Path, name: str, *, create: bool = False,
                   prefix: str = "") -> str:
    """Lee un token del estado local y, si procede, lo crea una sola vez."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not create:
            return ""
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        value = prefix + secrets.token_urlsafe(48)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return _managed_token(path, name, create=False)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(value + "\n")
            target.flush()
            os.fsync(target.fileno())
        return _validate_token(name, value)
    except OSError as exc:
        raise ConfigError(f"no se puede leer {path}") from exc
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_SECRET_BYTES):
        raise ConfigError(f"{path} debe ser un fichero regular y acotado")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"no se puede leer {path}") from exc
    if "\n" in value or "\r" in value:
        raise ConfigError(f"{path} debe contener un unico secreto")
    return _validate_token(name, value)


def write_managed_token(state_dir: Path, filename: str, name: str,
                        value: str) -> str:
    """Guarda de forma atomica un secreto introducido desde el portal."""
    normalized = _validate_token(name, str(value or "").strip())
    if not normalized:
        raise ConfigError(f"{name} no puede quedar vacio")
    directory = state_dir / "secrets"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / filename
    temporary = directory / f".{filename}.{os.getpid()}.new"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(normalized + "\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        (directory / f"{filename}{_DISABLED_SUFFIX}").unlink(missing_ok=True)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)
    return normalized


def disable_managed_token(state_dir: Path, filename: str) -> None:
    """Disable an optional token, including a legacy environment fallback."""
    directory = state_dir / "secrets"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / filename
    marker = directory / f"{filename}{_DISABLED_SUFFIX}"
    destination.unlink(missing_ok=True)
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write("disabled\n")
        target.flush()
        os.fsync(target.fileno())


def _selected_token(state_dir: Path, filename: str, name: str, *,
                    create: bool = False, prefix: str = "") -> str:
    """Prefer portal-managed state and retain environment only for migration."""
    path = state_dir / "secrets" / filename
    managed = _managed_token(path, name)
    if managed:
        return managed
    marker = path.with_name(f"{path.name}{_DISABLED_SUFFIX}")
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ConfigError(f"no se puede leer {marker}") from exc
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ConfigError(f"{marker} debe ser un fichero regular")
        return ""
    environment = _token(name)
    if environment:
        return environment
    return _managed_token(path, name, create=create, prefix=prefix)


def _validate_ca_pem(value: str) -> str:
    normalized = str(value or "").strip()
    encoded = normalized.encode("utf-8")
    if not normalized or len(encoded) > _MAX_CA_BYTES or "\x00" in normalized:
        raise ConfigError("la CA privada debe ser un PEM no vacio de hasta 4 MiB")
    try:
        ssl.create_default_context(cadata=normalized)
    except (ssl.SSLError, ValueError) as exc:
        raise ConfigError("la CA privada no contiene certificados PEM validos") from exc
    return normalized + "\n"


def write_managed_ca(state_dir: Path, value: str) -> str:
    """Store a private CA supplied from the authenticated portal."""
    normalized = _validate_ca_pem(value)
    directory = state_dir / "tls"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / _MANAGED_CA_FILE
    temporary = directory / f".{_MANAGED_CA_FILE}.{os.getpid()}.new"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(normalized)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        (directory / f"{_MANAGED_CA_FILE}{_DISABLED_SUFFIX}").unlink(
            missing_ok=True)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)
    return str(destination)


def disable_managed_ca(state_dir: Path) -> None:
    directory = state_dir / "tls"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / _MANAGED_CA_FILE
    marker = directory / f"{_MANAGED_CA_FILE}{_DISABLED_SUFFIX}"
    destination.unlink(missing_ok=True)
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write("disabled\n")
        target.flush()
        os.fsync(target.fileno())


def _ca_file(state_dir: Path) -> str | None:
    managed = state_dir / "tls" / _MANAGED_CA_FILE
    marker = managed.with_name(f"{managed.name}{_DISABLED_SUFFIX}")
    if managed.exists():
        value = str(managed)
    elif marker.exists():
        return None
    else:
        value = os.getenv("VG_CA_FILE", "").strip()
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise ConfigError("VG_CA_FILE debe ser una ruta absoluta")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigError("no se puede leer VG_CA_FILE") from exc
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_CA_BYTES):
        raise ConfigError("VG_CA_FILE debe ser un fichero regular y acotado")
    return str(path)


def _docker_socket(value: str) -> str:
    raw = str(value or "").strip()
    path = Path(raw)
    if not raw or not path.is_absolute() or any(
        character in raw for character in "\x00\r\n\t"
    ):
        raise ConfigError("VG_DOCKER_SOCKET debe ser una ruta absoluta")
    return str(path)


def _inside_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        try:
            if os.path.commonpath((str(root), str(path))) == str(root):
                return True
        except ValueError:
            continue
    return False


def _parse_data_roots(value: str) -> tuple[Path, ...]:
    roots = []
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        raw = Path(entry)
        if not raw.is_absolute():
            raise ConfigError(f"VG_DATA_ROOTS contiene una ruta no absoluta: {entry!r}")
        root = raw.resolve()
        roots.append(root)
    if not roots:
        raise ConfigError("VG_DATA_ROOTS debe declarar al menos una raíz")
    return tuple(dict.fromkeys(roots))


@dataclass(frozen=True)
class Instance:
    id: str
    container: str
    data_dir: Path
    health_port: int
    health_path: str
    floating_service: str
    include_sends: bool = True
    replication_enabled: bool = False
    display_name: str = ""
    data_backend: str = "auto"

    @classmethod
    def from_dict(cls, raw: dict) -> "Instance":
        if not isinstance(raw, dict):
            raise ConfigError("cada instancia debe ser un objeto JSON")
        required = ("id", "container", "data_dir", "health_port", "health_path")
        missing = [key for key in required if not raw.get(key)]
        if missing:
            raise ConfigError(f"instancia incompleta: faltan {', '.join(missing)}")
        identifier = str(raw["id"])
        container = str(raw["container"])
        service = str(raw.get("floating_service") or identifier)
        display_name = str(raw.get("display_name") or identifier).strip()
        if not _NAME.fullmatch(identifier):
            raise ConfigError(f"id de instancia no válido: {identifier!r}")
        if not _NAME.fullmatch(container):
            raise ConfigError(f"nombre de contenedor no válido: {container!r}")
        if not _NAME.fullmatch(service):
            raise ConfigError(f"servicio floating-ip no válido: {service!r}")
        if not display_name or len(display_name) > 80 or any(ord(char) < 32 for char in display_name):
            raise ConfigError(f"nombre visible no válido para {identifier}")
        data_backend = str(raw.get("data_backend") or "auto").strip().lower()
        if data_backend not in {"auto", "direct", "docker"}:
            raise ConfigError(
                f"data_backend de {identifier} debe ser auto, direct o docker")
        raw_data_dir = Path(str(raw["data_dir"]))
        if not raw_data_dir.is_absolute():
            raise ConfigError(f"data_dir debe ser absoluto: {raw_data_dir}")
        data_dir = raw_data_dir.resolve()
        try:
            port = int(raw["health_port"])
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"puerto inválido para {identifier}") from exc
        if not 1 <= port <= 65535:
            raise ConfigError(f"puerto fuera de rango para {identifier}: {port}")
        path = str(raw["health_path"])
        if (not path.startswith("/") or path.startswith("//") or "#" in path
                or "\\" in path or any(character.isspace() for character in path)
                or any(ord(character) < 32 for character in path)):
            raise ConfigError(f"health_path inválida para {identifier}: {path!r}")
        include_sends = raw.get("include_sends", True)
        replication_enabled = raw.get("replication_enabled", False)
        if not isinstance(include_sends, bool):
            raise ConfigError(f"include_sends de {identifier} debe ser booleano")
        if not isinstance(replication_enabled, bool):
            raise ConfigError(f"replication_enabled de {identifier} debe ser booleano")
        return cls(
            identifier,
            container,
            data_dir,
            port,
            path,
            service,
            include_sends,
            replication_enabled,
            display_name,
            data_backend,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "container": self.container,
            "data_dir": str(self.data_dir),
            "health_port": self.health_port,
            "health_path": self.health_path,
            "floating_service": self.floating_service,
            "include_sends": self.include_sends,
            "replication_enabled": self.replication_enabled,
            "display_name": self.display_name or self.id,
            "data_backend": self.data_backend,
        }


def write_instances(filename: str | Path, instances: tuple[Instance, ...] | list[Instance]) -> None:
    items = tuple(instances)
    for label, values in (
        ("id", [item.id for item in items]),
        ("contenedor", [item.container for item in items]),
        ("servicio", [item.floating_service for item in items]),
    ):
        if len(values) != len(set(values)):
            raise ConfigError(f"{label} repetido en la configuración")
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    payload = {"format": 1, "instances": [item.to_dict() for item in items]}
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Settings:
    node: str
    node_ip: str
    instances_file: Path
    state_dir: Path
    settings_file: Path
    identity_configured: bool
    peers: dict[str, str]
    floating_api: str
    mode: str
    api_token: str
    replication_token: str
    session_minutes: int
    allow_insecure_portal: bool
    interval_seconds: int
    backup_retention: int
    max_package_bytes: int
    data_roots: tuple[Path, ...]
    instances: tuple[Instance, ...]
    vaultwarden_root: str = ""
    floating_api_token: str = ""
    allow_insecure_http: bool = False
    ca_file: str | None = None
    docker_socket: str = "/var/run/docker.sock"
    history_max_bytes: int = _DEFAULT_HISTORY_MAX_MB * 1024 * 1024
    history_max_entries: int = _DEFAULT_HISTORY_MAX_ENTRIES

    @classmethod
    def load(cls, filename: str | Path) -> "Settings":
        path = Path(filename)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"no se puede leer {path}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("format") != 1:
            raise ConfigError("instances.json requiere format=1")
        raw_instances = raw.get("instances", [])
        if not isinstance(raw_instances, list):
            raise ConfigError("instances.json requiere una lista en instances")
        data_roots = _parse_data_roots(os.getenv("VG_DATA_ROOTS", "/instances"))
        instances = tuple(Instance.from_dict(item) for item in raw_instances)
        for instance in instances:
            if not _inside_roots(instance.data_dir, data_roots):
                raise ConfigError(
                    f"data_dir de {instance.id} queda fuera de VG_DATA_ROOTS: {instance.data_dir}"
                )
        ids = [item.id for item in instances]
        containers = [item.container for item in instances]
        services = [item.floating_service for item in instances]
        for label, values in (("id", ids), ("contenedor", containers), ("servicio", services)):
            if len(values) != len(set(values)):
                raise ConfigError(f"{label} repetido en instances.json")

        raw_state_dir = Path(os.getenv("VG_STATE_DIR", str(path.parent)))
        if not raw_state_dir.is_absolute():
            raise ConfigError("VG_STATE_DIR debe ser una ruta absoluta")
        state_dir = raw_state_dir.resolve()
        allow_insecure_http = _boolean("VG_ALLOW_INSECURE_HTTP")
        settings_file = state_dir / "settings.json"
        try:
            operational = runtime_config.read(
                settings_file,
                allow_insecure_http=allow_insecure_http,
            )
            bootstrap_root = os.getenv("VG_VAULTWARDEN_ROOT", "").strip()
            if (
                operational is not None
                and not operational["vaultwarden_root"]
                and bootstrap_root
            ):
                operational = runtime_config.normalize(
                    {**operational, "vaultwarden_root": bootstrap_root},
                    allow_insecure_http=allow_insecure_http,
                )
            if operational is None:
                floating_environment = os.getenv("VG_FLOATING_API")
                floating_explicit = bool(
                    floating_environment and floating_environment.strip()
                )
                operational = runtime_config.normalize({
                    "node": os.getenv("VG_NODE", "").strip() or "local",
                    "node_ip": os.getenv("VG_NODE_IP", "").strip() or "127.0.0.1",
                    "peers": _parse_peers(
                        os.getenv("VG_PEERS", ""), allow_insecure_http
                    ),
                    "floating_api": (
                        floating_environment.strip()
                        if floating_explicit
                        else "http://host.docker.internal:6060"
                    ),
                    "mode": os.getenv("VG_MODE", "observe").strip(),
                    "interval_seconds": os.getenv("VG_INTERVAL_SECONDS", "30"),
                    "backup_retention": os.getenv("VG_BACKUP_RETENTION", "5"),
                    "max_package_mb": os.getenv("VG_MAX_PACKAGE_MB", "256"),
                    "vaultwarden_root": os.getenv("VG_VAULTWARDEN_ROOT", ""),
                }, allow_insecure_http=(
                    allow_insecure_http or not floating_explicit
                ))
        except runtime_config.RuntimeConfigError as exc:
            raise ConfigError(str(exc)) from exc
        identity_configured = bool(
            settings_file.exists() or os.getenv("VG_NODE", "").strip()
        )
        local_settings = _local_settings(state_dir)
        session_minutes = local_settings["session_minutes"]
        api_token = _selected_token(
            state_dir, "api-token", "VG_API_TOKEN")
        replication_token = _selected_token(
            state_dir,
            "replication-token",
            "VG_REPLICATION_TOKEN",
            create=True,
            prefix="vg_replication_",
        )
        floating_api_token = _selected_token(
            state_dir, "floating-api-token", "VG_FLOATING_API_TOKEN")
        named_tokens = {
            name: value for name, value in (
                ("VG_API_TOKEN", api_token),
                ("VG_REPLICATION_TOKEN", replication_token),
                ("VG_FLOATING_API_TOKEN", floating_api_token),
            ) if value
        }
        if len(set(named_tokens.values())) != len(named_tokens):
            raise ConfigError(
                "VG_API_TOKEN, VG_REPLICATION_TOKEN y VG_FLOATING_API_TOKEN "
                "deben ser distintos"
            )
        return cls(
            node=operational["node"],
            node_ip=operational["node_ip"],
            instances_file=path,
            state_dir=state_dir,
            settings_file=settings_file,
            identity_configured=identity_configured,
            peers=operational["peers"],
            floating_api=operational["floating_api"],
            mode=operational["mode"],
            backup_retention=operational["backup_retention"],
            session_minutes=session_minutes,
            allow_insecure_portal=_portal_access(state_dir),
            interval_seconds=operational["interval_seconds"],
            max_package_bytes=operational["max_package_mb"] * 1024 * 1024,
            data_roots=data_roots,
            instances=instances,
            vaultwarden_root=operational["vaultwarden_root"],
            allow_insecure_http=operational["allow_insecure_http"],
            ca_file=_ca_file(state_dir),
            api_token=api_token,
            replication_token=replication_token,
            floating_api_token=floating_api_token,
            docker_socket=_docker_socket(os.getenv(
                "VG_DOCKER_SOCKET", "/var/run/docker.sock"
            )),
            history_max_bytes=local_settings["history_max_mb"] * 1024 * 1024,
            history_max_entries=local_settings["history_max_entries"],
        )


def _parse_peers(value: str, allow_insecure_http: bool = False) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise ConfigError(f"par sin '=' en VG_PEERS: {entry!r}")
        name, url = (part.strip() for part in entry.split("=", 1))
        try:
            url = http_client.normalize_base_url(
                url,
                allow_http=allow_insecure_http,
                label=f"URL del par {name or '?'}",
            )
        except http_client.HttpClientError as exc:
            raise ConfigError(str(exc)) from exc
        if not _NAME.fullmatch(name):
            raise ConfigError(f"par inválido en VG_PEERS: {entry!r}")
        result[name] = url
    return result

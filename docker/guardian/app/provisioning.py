"""Descubrimiento y normalización segura de contenedores Vaultwarden."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass


class ProvisioningError(ValueError):
    """El contenedor no se puede clonar sin ampliar privilegios o ambigüedad."""


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_OFFICIAL_IMAGE = re.compile(
    r"^(?:(?:docker[.]io|registry-1[.]docker[.]io)/)?"
    r"(?:library/)?vaultwarden/server(?::[^@/]+|@sha256:[0-9a-f]{64})?$",
    re.IGNORECASE,
)
_IGNORED_ENV = {
    "PATH",
    "HOSTNAME",
    "HOME",
    "TERM",
    "DEBIAN_FRONTEND",
    "HOST_CONTAINERNAME",
    "HOST_HOSTNAME",
    "HOST_OS",
}


@dataclass(frozen=True)
class VaultwardenSpec:
    container: str
    display_image: str
    pinned_image: str
    host_port: int
    data_source: str
    environment: tuple[str, ...]
    running: bool

    @property
    def environment_keys(self) -> list[str]:
        return sorted(item.split("=", 1)[0] for item in self.environment)

    def public(self) -> dict:
        return {
            "container": self.container,
            "image": self.display_image,
            "pinned_image": self.pinned_image,
            "host_port": self.host_port,
            "data_source": self.data_source,
            "running": self.running,
            # Sólo nombres. Los valores pueden contener ADMIN_TOKEN, SMTP o
            # secretos de identidad y nunca salen por la API de inventario.
            "environment_keys": self.environment_keys,
            "environment_values_exposed": False,
        }

    def private(self) -> dict:
        """Especificación completa; sólo puede viajar dentro de un sobre sellado."""
        return {
            "format": 1,
            "container": self.container,
            "pinned_image": self.pinned_image,
            "host_port": self.host_port,
            "environment": list(self.environment),
        }

    @classmethod
    def from_private(cls, raw: dict) -> "VaultwardenSpec":
        if not isinstance(raw, dict) or raw.get("format") != 1:
            raise ProvisioningError("especificación privada no válida")
        container = str(raw.get("container") or "")
        pinned = str(raw.get("pinned_image") or "")
        if not _NAME.fullmatch(container):
            raise ProvisioningError("nombre de contenedor no válido")
        if "@sha256:" not in pinned or not _official_reference(pinned):
            raise ProvisioningError("la imagen privada no tiene un digest oficial")
        try:
            host_port = int(raw.get("host_port"))
        except (TypeError, ValueError) as exc:
            raise ProvisioningError("puerto privado no válido") from exc
        if not 1 <= host_port <= 65535:
            raise ProvisioningError("puerto privado fuera de rango")
        environment = raw.get("environment")
        if not isinstance(environment, list) or len(environment) > 256:
            raise ProvisioningError("entorno privado no válido")
        validated = {}
        for item in environment:
            if not isinstance(item, str) or "=" not in item:
                raise ProvisioningError("variable privada no válida")
            key, value = item.split("=", 1)
            if (
                not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key)
                or key in _IGNORED_ENV
                or key.startswith("HOST_")
                or "\x00" in value
            ):
                raise ProvisioningError(f"variable privada no válida: {key!r}")
            validated[key] = value
        return cls(
            container=container,
            display_image=pinned,
            pinned_image=pinned,
            host_port=host_port,
            data_source="",
            environment=tuple(
                f"{key}={validated[key]}" for key in sorted(validated)),
            running=False,
        )


def _container_name(payload: dict) -> str:
    name = str(payload.get("Name") or "").lstrip("/")
    if not _NAME.fullmatch(name):
        raise ProvisioningError("el contenedor no tiene un nombre seguro")
    return name


def _official_reference(reference: str) -> bool:
    return bool(_OFFICIAL_IMAGE.fullmatch(reference or ""))


def _pinned_image(container: dict, image: dict | None) -> str:
    configured = str((container.get("Config") or {}).get("Image") or "")
    digests = (image or {}).get("RepoDigests") or []
    candidates = [
        str(value) for value in digests
        if isinstance(value, str) and _official_reference(str(value))
    ]
    if "@sha256:" in configured and _official_reference(configured):
        return configured
    if candidates:
        return sorted(candidates)[0]
    raise ProvisioningError(
        "la imagen oficial no tiene digest verificable; tira la imagen antes de clonar")


def _data_mount(container: dict) -> str:
    mounts = container.get("Mounts") or []
    data = [
        item for item in mounts
        if isinstance(item, dict) and item.get("Destination") == "/data"
    ]
    if len(data) != 1:
        raise ProvisioningError("Vaultwarden debe tener un único volumen /data")
    mount = data[0]
    if mount.get("Type") != "bind" or not mount.get("RW"):
        raise ProvisioningError("/data debe ser una carpeta del servidor con escritura")
    source = str(mount.get("Source") or "")
    if not source.startswith("/") or source == "/" or "\x00" in source:
        raise ProvisioningError("la carpeta host de /data no es segura")
    extras = [
        item.get("Destination") for item in mounts
        if isinstance(item, dict) and item.get("Destination") != "/data"
    ]
    if extras:
        raise ProvisioningError(
            "el contenedor tiene montajes extra que Guardian no copiará: "
            + ", ".join(str(item) for item in extras)
        )
    return source


def _host_port(container: dict) -> int:
    bindings = ((container.get("HostConfig") or {}).get("PortBindings") or {})
    unexpected = [key for key, value in bindings.items() if value and key != "80/tcp"]
    if unexpected:
        raise ProvisioningError(
            "el contenedor publica puertos adicionales: " + ", ".join(unexpected))
    values = bindings.get("80/tcp") or []
    if len(values) != 1 or not isinstance(values[0], dict):
        raise ProvisioningError("Vaultwarden debe publicar una sola vez el puerto 80/tcp")
    host_ip = str(values[0].get("HostIp") or "")
    if host_ip not in {"", "0.0.0.0", "::"}:  # nosec B104 - valida un bind Docker
        raise ProvisioningError(
            "el puerto está ligado a una IP concreta del servidor")
    try:
        port = int(values[0].get("HostPort"))
    except (TypeError, ValueError) as exc:
        raise ProvisioningError("el puerto publicado no es válido") from exc
    if not 1 <= port <= 65535:
        raise ProvisioningError("el puerto publicado queda fuera de rango")
    return port


def _safe_environment(container: dict) -> tuple[str, ...]:
    result = {}
    for item in (container.get("Config") or {}).get("Env") or []:
        if not isinstance(item, str) or "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key in _IGNORED_ENV or key.startswith("HOST_"):
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            raise ProvisioningError(f"variable de entorno no válida: {key!r}")
        if "\x00" in value:
            raise ProvisioningError(f"variable {key} contiene un valor no válido")
        result[key] = value
    return tuple(f"{key}={result[key]}" for key in sorted(result))


def normalize(container: dict, image: dict | None) -> VaultwardenSpec:
    if not isinstance(container, dict):
        raise ProvisioningError("Docker inspect no devolvió un contenedor")
    config = container.get("Config") or {}
    host = container.get("HostConfig") or {}
    configured_image = str(config.get("Image") or "")
    if not _official_reference(configured_image):
        raise ProvisioningError("no usa la imagen oficial vaultwarden/server")
    if host.get("Privileged"):
        raise ProvisioningError("un contenedor privilegiado no se clona")
    if str(host.get("NetworkMode") or "") != "bridge":
        raise ProvisioningError("Vaultwarden debe usar red bridge")
    if host.get("CapAdd"):
        raise ProvisioningError("un contenedor con capacidades añadidas no se clona")
    if host.get("Devices"):
        raise ProvisioningError("un contenedor con dispositivos no se clona")
    configured_user = str(config.get("User") or "").strip()
    if configured_user not in {"", "0", "0:0", "root", "root:root"}:
        raise ProvisioningError(
            "el usuario personalizado de Vaultwarden no se puede preservar "
            "con permisos seguros"
        )
    if container.get("Path") != "/start.sh" or (container.get("Args") or []):
        raise ProvisioningError("el arranque personalizado no se clona")
    state = container.get("State") or {}
    return VaultwardenSpec(
        container=_container_name(container),
        display_image=configured_image,
        pinned_image=_pinned_image(container, image),
        host_port=_host_port(container),
        data_source=_data_mount(container),
        environment=_safe_environment(container),
        running=bool(state.get("Running")),
    )


def candidate(container: dict, image: dict | None) -> dict:
    name = str(container.get("Name") or "").lstrip("/") or "desconocido"
    configured_image = str((container.get("Config") or {}).get("Image") or "")
    if not _official_reference(configured_image):
        return {"container": name, "vaultwarden": False}
    try:
        spec = normalize(container, image)
    except ProvisioningError as exc:
        return {
            "container": name,
            "vaultwarden": True,
            "eligible": False,
            "blockers": [str(exc)],
        }
    return {
        "vaultwarden": True,
        "eligible": True,
        "blockers": [],
        **spec.public(),
    }


def target_data_path(root: str, directory: str) -> str:
    """Compone una ruta host sin permitir escapes ni usar la raíz."""
    normalized_root = posixpath.normpath(str(root or "").strip())
    if (
        not normalized_root.startswith("/")
        or normalized_root == "/"
        or any(char in normalized_root for char in ("\x00", "\r", "\n", ":"))
    ):
        raise ProvisioningError(
            "este servidor no tiene una raíz host segura para Vaultwarden")
    if not _NAME.fullmatch(str(directory or "")):
        raise ProvisioningError("el nombre de la carpeta de datos no es válido")
    target = posixpath.normpath(posixpath.join(normalized_root, directory))
    try:
        inside = posixpath.commonpath((normalized_root, target)) == normalized_root
    except ValueError:
        inside = False
    if not inside or target == normalized_root:
        raise ProvisioningError("la carpeta de datos queda fuera de la raíz permitida")
    return target


def exact_target_data_path(value: str) -> str:
    """Valida una carpeta host completa elegida para una nueva réplica."""
    raw = str(value or "").strip()
    target = posixpath.normpath(raw)
    parts = raw.split("/")
    if (
        not raw.startswith("/")
        or target == "/"
        or any(char in raw for char in ("\x00", "\r", "\n", ":"))
        or any(part in {".", ".."} for part in parts)
    ):
        raise ProvisioningError(
            "la ruta host de destino debe ser absoluta, concreta y segura")
    return target


def container_create_spec(
    source: VaultwardenSpec,
    *,
    transaction: str,
    target_path: str,
) -> dict:
    """Devuelve la lista blanca exacta que se entregará a Docker."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", transaction or ""):
        raise ProvisioningError("identificador de transacción no válido")
    if (
        not target_path.startswith("/")
        or target_path == "/"
        or any(char in target_path for char in ("\x00", "\r", "\n", ":"))
    ):
        raise ProvisioningError("ruta de datos de destino no válida")
    return {
        "Image": source.pinned_image,
        "Env": list(source.environment),
        "ExposedPorts": {"80/tcp": {}},
        "Labels": {
            "com.vault-guardian.managed": "true",
            "com.vault-guardian.transaction": transaction,
        },
        "HostConfig": {
            "NetworkMode": "bridge",
            "PortBindings": {
                "80/tcp": [{
                    "HostIp": "",
                    "HostPort": str(source.host_port),
                }],
            },
            "Binds": [f"{target_path}:/data:rw"],
            "Privileged": False,
            "CapAdd": [],
            "Devices": [],
            "SecurityOpt": ["no-new-privileges:true"],
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
        },
    }

"""Coordinación de snapshots y configuración operativa."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import docker_api
import data_access
import api_integrations
import cluster
import floating
import http_client
import provisioning
import provisioning_local
import sealed
import snapshot
import readiness
import runtime_config
from config import (
    ConfigError,
    Instance,
    Settings,
    disable_managed_ca,
    disable_managed_token,
    write_local_settings,
    write_managed_ca,
    write_instances,
    write_managed_token,
    write_portal_access,
)
from state import StateError, StateStore


class ReplicationError(RuntimeError):
    """Una réplica no se puede iniciar o aplicar con seguridad."""


_BACKUP_NAME = re.compile(r"^antes-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?[.]vgb$")
_NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_POLICY_FIELDS = (
    "mode",
    "interval_seconds",
    "backup_retention",
    "max_package_mb",
)
_PROVISION_TRANSACTION = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_PROVISION_FIELDS = {
    "source_container",
    "instance_id",
    "display_name",
    "data_directory",
    "destination_paths",
    "health_path",
    "include_sends",
    "confirm",
}


def _read_package_file(path: Path, max_bytes: int) -> bytes:
    """Lee un paquete regular sin seguir enlaces ni reservar memoria sin cota."""
    if max_bytes < 1:
        raise ReplicationError("el límite del paquete no es válido")
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size > max_bytes
        ):
            raise ReplicationError("el paquete persistido no es un fichero regular seguro")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReplicationError("no se puede abrir el paquete persistido de forma segura") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > max_bytes
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ReplicationError("el paquete persistido cambió o supera el límite")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ReplicationError("el paquete persistido supera el límite")
        return payload
    except OSError as exc:
        raise ReplicationError("no se puede leer el paquete persistido de forma segura") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@dataclass
class LastResult:
    at: str
    result: dict


class ReplicationManager:
    def __init__(self, settings: Settings, docker: docker_api.DockerClient | None = None):
        self.settings = settings
        self.docker = docker or docker_api.DockerClient(
            getattr(settings, "docker_socket", "/var/run/docker.sock"),
            allow_local_socket=True,
        )
        self._last: dict[str, LastResult] = {}
        self._lock = threading.RLock()
        self._instance_locks: dict[str, threading.RLock] = {}
        self._state = self._new_state_store()
        self._data = data_access.ContainerData(self.docker)
        self._api_integrations = api_integrations.ApiIntegrationStore(
            settings.state_dir)
        try:
            self._api_integrations.import_legacy(
                getattr(settings, "api_token", ""))
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc
        self._provisioning = provisioning_local.LocalProvisioner(
            settings, self.docker, self._data, self._state)

    def _operation_lock(self) -> threading.RLock:
        if not hasattr(self, "_lock"):
            self._lock = threading.RLock()
        return self._lock

    def _instance_operation_lock(self, instance_id: str) -> threading.RLock:
        with self._operation_lock():
            if not hasattr(self, "_instance_locks"):
                self._instance_locks = {}
            return self._instance_locks.setdefault(instance_id, threading.RLock())

    def _new_state_store(self) -> StateStore:
        return StateStore(
            self.settings.state_dir,
            getattr(self.settings, "node", "local"),
            getattr(self.settings, "history_max_bytes", 16 * 1024 * 1024),
            getattr(self.settings, "history_max_entries", 5_000),
        )

    def _local_provisioner(self) -> provisioning_local.LocalProvisioner:
        if not hasattr(self, "_provisioning"):
            self._provisioning = provisioning_local.LocalProvisioner(
                self.settings, self.docker, self._data_access(), self._state_store())
        return self._provisioning

    def _state_store(self) -> StateStore:
        if not hasattr(self, "_state"):
            self._state = self._new_state_store()
        return self._state

    def _data_access(self) -> data_access.ContainerData:
        if not hasattr(self, "_data"):
            if not hasattr(self, "docker"):
                self.docker = docker_api.DockerClient(
                    getattr(self.settings, "docker_socket", "/var/run/docker.sock"),
                    allow_local_socket=True,
                )
            self._data = data_access.ContainerData(self.docker)
        return self._data

    def _api_integration_store(self) -> api_integrations.ApiIntegrationStore:
        if not hasattr(self, "_api_integrations"):
            self._api_integrations = api_integrations.ApiIntegrationStore(
                self.settings.state_dir)
            try:
                self._api_integrations.import_legacy(
                    getattr(self.settings, "api_token", ""))
            except api_integrations.ApiIntegrationError as exc:
                raise ConfigError(str(exc)) from exc
        return self._api_integrations

    def instance(self, instance_id: str) -> Instance:
        for item in self.settings.instances:
            if item.id == instance_id:
                return item
        raise ReplicationError(f"instancia desconocida: {instance_id}")

    def floating_state(self, instance: Instance) -> floating.FloatingState:
        return floating.get_state(
            self.settings.floating_api,
            instance.floating_service,
            self.settings.node,
            api_token=getattr(self.settings, "floating_api_token", ""),
            allow_insecure_http=bool(
                getattr(self.settings, "allow_insecure_http", False)),
            ca_file=getattr(self.settings, "ca_file", None),
        )

    def status(self) -> dict:
        result = []
        for instance in self.settings.instances:
            event = self._state_store().last_result(instance.id)
            last_result = event.get("result") if event else (
                self._last.get(instance.id).result if instance.id in self._last else None
            )
            if (
                isinstance(last_result, dict)
                and last_result.get("estado") == "omitido"
                and last_result.get("motivo") == "este nodo no es el portador"
            ):
                last_result = {
                    **last_result,
                    "estado": "en_espera",
                    "motivo": "este Guardian espera al portador de la IP",
                }
            try:
                state = self.floating_state(instance)
                state_data = state.as_dict()
            except floating.FloatingError as exc:
                state_data = {"servicio": instance.floating_service, "conocido": False,
                              "portador": None, "salud_local": None, "detalle": str(exc)}
            result.append({
                "id": instance.id,
                "nombre": instance.display_name or instance.id,
                "contenedor": instance.container,
                "puerto_salud": instance.health_port,
                "ruta_salud": instance.health_path,
                "replicacion": instance.replication_enabled,
                "floating_ip": state_data,
                "último_resultado": last_result,
                "last_event": event,
                "contenido": self._state_store().content(instance.id),
            })
        return {"nodo": self.settings.node, "modo": self.settings.mode,
                "configurado": bool(self.settings.instances),
                "estado_configuracion": "lista" if self.settings.instances else "pendiente",
                "instancias": result, "pares": sorted(self.settings.peers),
                "topologia": {
                    "node_ip": self.settings.node_ip,
                    "floating_api": self.settings.floating_api,
                    "vaultwarden_root": self.settings.vaultwarden_root,
                },
                "politica": self._shared_policy()}


    def cluster_status(self) -> dict:
        return cluster.collect_cluster(
            self.status(),
            self.settings.peers,
            self.settings.replication_token,
            bool(getattr(self.settings, "allow_insecure_http", False)),
            getattr(self.settings, "ca_file", None),
        )

    def history(self, limit: int = 100) -> dict:
        bounded = max(1, min(int(limit), 500))
        try:
            items = self._state_store().history(bounded)
        except StateError as exc:
            raise ReplicationError("el historial local no está disponible") from exc
        return {"items": items, "limit": bounded}

    def _portal_configured(self) -> bool:
        path = Path(getattr(self.settings, "state_dir", "/state")) / "auth.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return bool(
            isinstance(payload, dict)
            and isinstance(payload.get("users"), list)
            and payload["users"]
        )

    def config(self) -> dict:
        integration_count = len(self.list_api_integrations()["items"])
        return {
            "format": 1,
            "instancias": [item.to_dict() for item in self.settings.instances],
            "raices_datos": [str(root) for root in self.settings.data_roots],
            "nodo": self.settings.node,
            "modo": self.settings.mode,
            "pares": dict(sorted(self.settings.peers.items())),
            "token_api_configurado": integration_count > 0,
            "integraciones_api_configuradas": integration_count,
            "portal_configurado": self._portal_configured(),
            "token_replicacion_configurado": bool(self.settings.replication_token),
            "token_ip_flotante_configurado": bool(
                getattr(self.settings, "floating_api_token", "")),
            "backup_retention": self.settings.backup_retention,
            "identidad_configurada": self.settings.identity_configured,
            "configuracion_operativa": self._operational_settings(),
            "configuracion_persistente": self.settings.settings_file.exists(),
            "raiz_host_vaultwarden": self.settings.vaultwarden_root,
            "ajustes_aplicacion": {
                "session_minutes": self.settings.session_minutes,
                "history_max_mb": (
                    self.settings.history_max_bytes // (1024 * 1024)
                ),
                "history_max_entries": self.settings.history_max_entries,
                "allow_insecure_portal": self.settings.allow_insecure_portal,
                "api_token_configured": integration_count > 0,
                "api_integration_count": integration_count,
                "private_ca_configured": bool(self.settings.ca_file),
            },
        }

    def _operational_settings(self) -> dict:
        return {
            "node": self.settings.node,
            "node_ip": self.settings.node_ip,
            "peers": dict(sorted(self.settings.peers.items())),
            "floating_api": self.settings.floating_api,
            "mode": self.settings.mode,
            "interval_seconds": self.settings.interval_seconds,
            "backup_retention": self.settings.backup_retention,
            "max_package_mb": self.settings.max_package_bytes // (1024 * 1024),
            "vaultwarden_root": self.settings.vaultwarden_root,
            "allow_insecure_http": bool(
                getattr(self.settings, "allow_insecure_http", False)),
        }

    def _shared_policy(self) -> dict:
        operational = self._operational_settings()
        return {key: operational[key] for key in _POLICY_FIELDS}

    def setup_status(self) -> dict:
        data_mount = (
            self._data_access().mount_available()
            if hasattr(self, "docker") else False
        )
        mounted_roots = (
            [str(root) for root in self.settings.data_roots]
            if data_mount else []
        )
        checks = {
            "api_token": bool(self.list_api_integrations()["items"]),
            "portal_account": self._portal_configured(),
            "identity": self.settings.identity_configured,
            "data_mount": data_mount,
            "data_access": data_mount,
            "peers": len(self.settings.peers) > 0,
            "instances": len(self.settings.instances) > 0,
            "replication_token": bool(self.settings.replication_token),
            "provisioning_root": bool(getattr(self.settings, "vaultwarden_root", "")),
            "floating_api_token": bool(
                getattr(self.settings, "floating_api_token", "")),
        }
        requirements = {
            "api_token": False,  # nosec B105 - indicador de requisito, no credencial
            "portal_account": True,
            "identity": True,
            "data_mount": False,
            "data_access": True,
            # Un segundo Guardian aporta redundancia, pero no es un requisito
            # para que la primera instalación sea operativa.
            "peers": False,
            "instances": True,
            # También cifra la instantánea inicial en modo mononodo.
            "replication_token": True,  # nosec B105 - indicador de requisito
            # La ruta de cada destino se exige sólo al crear esa réplica.
            "provisioning_root": False,
            "floating_api_token": True,  # nosec B105 - indicador de requisito
        }
        required_ready = all(
            checks[key] for key, required in requirements.items() if required
        )
        any_progress = any(
            checks[key] for key, required in requirements.items() if required
        )
        return {
            "state": (
                "ready" if required_ready
                else "in_progress" if any_progress
                else "empty"
            ),
            "checks": checks,
            "requirements": requirements,
            "mounted_data_roots": mounted_roots,
            "instance_count": len(self.settings.instances),
            "peer_count": len(self.settings.peers),
            "redundancy": "cluster" if self.settings.peers else "single_node",
            "mode": self.settings.mode,
            "ready_for_inventory": all(
                checks[key] for key in ("portal_account", "identity", "data_access")
            ),
            "ready_for_active": required_ready,
        }

    def update_settings(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._update_settings(raw)

    def update_keepalived_integration(self, raw: dict) -> dict:
        """Persiste el Bearer local sin exponerlo en la configuracion publica."""
        if not isinstance(raw, dict) or set(raw) != {"token"}:
            raise ConfigError("la integracion requiere unicamente token")
        with self._operation_lock():
            write_managed_token(
                self.settings.state_dir,
                "floating-api-token",
                "VG_FLOATING_API_TOKEN",
                str(raw.get("token") or ""),
            )
            with self._lock:
                self.settings = Settings.load(self.settings.instances_file)
                self._state = self._new_state_store()
                self._provisioning = provisioning_local.LocalProvisioner(
                    self.settings, self.docker, self._data_access(), self._state)
        return {
            "configured": bool(self.settings.floating_api_token),
            "floating_api": self.settings.floating_api,
        }

    def update_application_settings(self, raw: dict) -> dict:
        """Persist portal-local settings formerly supplied as Docker variables."""
        if not isinstance(raw, dict):
            raise ConfigError("los ajustes de la aplicacion deben ser un objeto")
        allowed = {
            "session_minutes",
            "history_max_mb",
            "history_max_entries",
            "allow_insecure_portal",
        }
        unknown = sorted(set(raw) - allowed)
        if unknown or set(raw) != allowed:
            raise ConfigError(
                "los ajustes requieren sesion, historial y acceso del portal")
        if type(raw.get("allow_insecure_portal")) is not bool:
            raise ConfigError("allow_insecure_portal debe ser true o false")
        with self._operation_lock():
            write_local_settings(self.settings.state_dir, {
                "session_minutes": raw.get("session_minutes"),
                "history_max_mb": raw.get("history_max_mb"),
                "history_max_entries": raw.get("history_max_entries"),
            })
            write_portal_access(
                self.settings.state_dir, raw["allow_insecure_portal"])
            self._reload_settings()
        return self.config()["ajustes_aplicacion"]

    def update_api_integration(self, raw: dict) -> dict:
        if not isinstance(raw, dict) or set(raw) != {"token"}:
            raise ConfigError("la integracion API requiere unicamente token")
        token = str(raw.get("token") or "").strip()
        if token in {
            self.settings.replication_token,
            self.settings.floating_api_token,
        }:
            raise ConfigError("el token API debe ser distinto de los otros secretos")
        with self._operation_lock():
            try:
                identifiers = {
                    item["id"] for item in self._api_integration_store().list()
                }
                if "legacy_api_token" in identifiers:
                    self._api_integration_store().update(
                        "legacy_api_token", token=token)
                else:
                    self._api_integration_store().import_legacy(token)
            except api_integrations.ApiIntegrationError as exc:
                raise ConfigError(str(exc)) from exc
            write_managed_token(
                self.settings.state_dir, "api-token", "VG_API_TOKEN", token)
            self._reload_settings()
        return {"configured": True}

    def disable_api_integration(self) -> dict:
        with self._operation_lock():
            try:
                identifiers = {
                    item["id"] for item in self._api_integration_store().list()
                }
                if "legacy_api_token" in identifiers:
                    self._api_integration_store().delete("legacy_api_token")
            except api_integrations.ApiIntegrationError as exc:
                raise ConfigError(str(exc)) from exc
            disable_managed_token(self.settings.state_dir, "api-token")
            self._reload_settings()
        return {
            "configured": bool(self.list_api_integrations()["items"]),
        }

    def list_api_integrations(self) -> dict:
        try:
            return {"items": self._api_integration_store().list()}
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc

    def authenticate_api_integration(self, token: str, endpoint: str = "") -> bool:
        try:
            return bool(self._api_integration_store().authenticate(token, endpoint))
        except api_integrations.ApiIntegrationError:
            return False

    def create_api_integration(self, raw: dict) -> dict:
        if not isinstance(raw, dict) or not set(raw).issubset({"name", "token"}):
            raise ConfigError("la aplicación requiere nombre y un token opcional")
        if "name" not in raw:
            raise ConfigError("la aplicación requiere un nombre")
        token = str(raw.get("token") or "").strip()
        if token and token in {
            self.settings.replication_token,
            self.settings.floating_api_token,
        }:
            raise ConfigError("el token API debe ser distinto de los otros secretos")
        try:
            item, issued_token = self._api_integration_store().create(
                raw.get("name"), token)
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc
        return {"application": item, "token": issued_token}

    def update_api_application(self, identifier: str, raw: dict) -> dict:
        if (
            not isinstance(raw, dict)
            or not raw
            or not set(raw).issubset({"name", "token"})
        ):
            raise ConfigError("la edición admite nombre y token")
        requested = (
            str(raw.get("token") or "").strip()
            if "token" in raw else None
        )
        if requested is not None and not requested:
            raise ConfigError("el nuevo token no puede quedar vacío")
        if requested and requested in {
            self.settings.replication_token,
            self.settings.floating_api_token,
        }:
            raise ConfigError("el token API debe ser distinto de los otros secretos")
        try:
            item, replacement = self._api_integration_store().update(
                identifier,
                name=raw.get("name") if "name" in raw else None,
                token=requested,
            )
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc
        if item["legacy"] and replacement:
            write_managed_token(
                self.settings.state_dir,
                "api-token",
                "VG_API_TOKEN",
                replacement,
            )
            self._reload_settings()
        result = {"application": item}
        if replacement:
            result["token"] = replacement
        return result

    def rotate_api_application(self, identifier: str, raw: dict) -> dict:
        if not isinstance(raw, dict) or not set(raw).issubset({"token"}):
            raise ConfigError("la rotación admite únicamente un token opcional")
        requested = str(raw.get("token") or "").strip()
        if requested and requested in {
            self.settings.replication_token,
            self.settings.floating_api_token,
        }:
            raise ConfigError("el token API debe ser distinto de los otros secretos")
        try:
            item, issued_token = self._api_integration_store().update(
                identifier, token=requested)
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc
        if item["legacy"]:
            write_managed_token(
                self.settings.state_dir,
                "api-token",
                "VG_API_TOKEN",
                issued_token or "",
            )
            self._reload_settings()
        return {"application": item, "token": issued_token}

    def reveal_api_application(self, identifier: str) -> dict:
        try:
            return {"token": self._api_integration_store().reveal(identifier)}
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc

    def delete_api_application(self, identifier: str) -> dict:
        try:
            item = self._api_integration_store().delete(identifier)
        except api_integrations.ApiIntegrationError as exc:
            raise ConfigError(str(exc)) from exc
        if item["legacy"]:
            disable_managed_token(self.settings.state_dir, "api-token")
            self._reload_settings()
        return {"deleted": identifier}

    def update_private_ca(self, raw: dict) -> dict:
        if not isinstance(raw, dict) or set(raw) != {"pem"}:
            raise ConfigError("la CA privada requiere unicamente pem")
        with self._operation_lock():
            write_managed_ca(self.settings.state_dir, str(raw.get("pem") or ""))
            self._reload_settings()
        return {"configured": bool(self.settings.ca_file)}

    def disable_private_ca(self) -> dict:
        with self._operation_lock():
            disable_managed_ca(self.settings.state_dir)
            self._reload_settings()
        return {"configured": False}

    def _reload_settings(self) -> None:
        """Reload mutable application state without recreating the container."""
        with self._lock:
            self.settings = Settings.load(self.settings.instances_file)
            self._state = self._new_state_store()
            self._provisioning = provisioning_local.LocalProvisioner(
                self.settings, self.docker, self._data_access(), self._state)

    def configure_enrollment_token(self, token: str) -> None:
        """Adopta el secreto de un grupo antes de crear la primera cuenta."""
        auth_file = self.settings.state_dir / "auth.json"
        if auth_file.exists():
            try:
                auth_state = json.loads(auth_file.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ConfigError("no se puede comprobar el estado de cuentas") from exc
            if isinstance(auth_state, dict) and auth_state.get("users"):
                raise ConfigError(
                    "el secreto del grupo no puede cambiar despues de crear cuentas")
        write_managed_token(
            self.settings.state_dir,
            "replication-token",
            "VG_REPLICATION_TOKEN",
            token,
        )
        self.settings = Settings.load(self.settings.instances_file)

    def enrollment_token(self) -> str:
        if not self.settings.replication_token:
            raise ConfigError("el secreto del grupo no esta disponible")
        return self.settings.replication_token

    def _update_settings(self, raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ConfigError("la configuración debe ser un objeto")
        candidate = dict(raw)
        confirm_active = candidate.pop("confirm_active", False) is True
        merged = self._operational_settings()
        merged.update(candidate)
        if (
            self.settings.instances
            and merged.get("node") != self.settings.node
        ):
            raise ConfigError(
                "no se puede cambiar la identidad con instancias configuradas"
            )
        if (
            merged.get("mode") == "active"
            and self.settings.mode != "active"
            and not confirm_active
        ):
            raise ConfigError("activar requiere confirm_active=true")
        try:
            runtime_config.write(
                self.settings.settings_file,
                merged,
                allow_insecure_http=bool(
                    getattr(self.settings, "allow_insecure_http", False)
                ),
            )
        except runtime_config.RuntimeConfigError as exc:
            raise ConfigError(str(exc)) from exc
        with self._lock:
            self.settings = Settings.load(self.settings.instances_file)
            self._state = self._new_state_store()
            self._provisioning = provisioning_local.LocalProvisioner(
                self.settings, self.docker, self._data_access(), self._state)
        return self.config()

    def _validate_full_settings(self, raw: dict, confirm_active: bool) -> dict:
        try:
            normalized = runtime_config.normalize(
                raw,
                allow_insecure_http=bool(
                    getattr(self.settings, "allow_insecure_http", False)
                ),
            )
        except runtime_config.RuntimeConfigError as exc:
            raise ConfigError(str(exc)) from exc
        if self.settings.instances and normalized["node"] != self.settings.node:
            raise ConfigError(
                "no se puede cambiar la identidad con instancias configuradas"
            )
        if (
            normalized["mode"] == "active"
            and self.settings.mode != "active"
            and not confirm_active
        ):
            raise ConfigError("activar requiere confirm_active=true")
        return normalized

    def internal_settings(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._internal_settings(raw)

    def _internal_settings(self, raw: dict) -> dict:
        if not isinstance(raw, dict) or not isinstance(raw.get("settings"), dict):
            raise ConfigError("settings debe ser un objeto")
        apply = raw.get("apply") is True
        confirm_active = raw.get("confirm_active") is True
        normalized = self._validate_full_settings(raw["settings"], confirm_active)
        if apply:
            result = self.update_settings({**normalized, "confirm_active": confirm_active})
        else:
            result = {"nodo": normalized["node"]}
        return {
            "estado": "aplicado" if apply else "validado",
            "nodo": normalized["node"],
            "config": result if apply else None,
        }

    def _validate_policy(self, raw: dict) -> tuple[dict, bool]:
        if not isinstance(raw, dict):
            raise ConfigError("la política debe ser un objeto")
        unknown = sorted(set(raw) - set(_POLICY_FIELDS) - {"confirm_active"})
        if unknown:
            raise ConfigError("campos de política no permitidos: " + ", ".join(unknown))
        confirm_active = raw.get("confirm_active") is True
        candidate = self._operational_settings()
        candidate.update({key: raw[key] for key in _POLICY_FIELDS if key in raw})
        normalized = self._validate_full_settings(candidate, confirm_active)
        return ({key: normalized[key] for key in _POLICY_FIELDS}, confirm_active)

    def internal_policy(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._internal_policy(raw)

    def _internal_policy(self, raw: dict) -> dict:
        if not isinstance(raw, dict) or not isinstance(raw.get("policy"), dict):
            raise ConfigError("policy debe ser un objeto")
        policy_raw = dict(raw["policy"])
        policy_raw["confirm_active"] = raw.get("confirm_active") is True
        policy, confirm_active = self._validate_policy(policy_raw)
        apply = raw.get("apply") is True
        if apply:
            self.update_settings({**policy, "confirm_active": confirm_active})
        return {
            "estado": "aplicado" if apply else "validado",
            "nodo": self.settings.node,
            "politica": policy,
        }

    def update_cluster_policy(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._update_cluster_policy(raw)

    def _update_cluster_policy(self, raw: dict) -> dict:
        policy, confirm_active = self._validate_policy(raw)
        if self.settings.peers and not self.settings.replication_token:
            raise ReplicationError("falta la contraseña entre Guardian")
        payload = {
            "policy": policy,
            "confirm_active": confirm_active,
            "apply": False,
        }
        validated = {}
        for peer, base_url in self.settings.peers.items():
            validated[peer] = self._send_peer_json(
                peer, base_url, "/api/v1/internal/policy", payload, method="PUT"
            )
        applied = {}
        payload["apply"] = True
        for peer, base_url in self.settings.peers.items():
            applied[peer] = self._send_peer_json(
                peer, base_url, "/api/v1/internal/policy", payload, method="PUT"
            )
        local = self.update_settings({**policy, "confirm_active": confirm_active})
        return {
            "estado": "aplicado_en_grupo",
            "nodos": 1 + len(applied),
            "politica": policy,
            "validacion": validated,
            "aplicacion": applied,
            "config": local,
        }

    @staticmethod
    def _member(raw: dict, allow_insecure_http: bool = False) -> dict:
        if not isinstance(raw, dict):
            raise ConfigError("cada servidor debe ser un objeto")
        name = str(raw.get("name", "")).strip()
        guardian_url = str(raw.get("guardian_url", "")).strip().rstrip("/")
        node_ip = str(raw.get("node_ip", "")).strip()
        floating_api = str(raw.get("floating_api", "")).strip().rstrip("/")
        vaultwarden_root = str(raw.get("vaultwarden_root") or "").strip()
        if not _NODE_NAME.fullmatch(name):
            raise ConfigError("cada servidor necesita un nombre estable")
        for label, value in (
            ("guardian_url", guardian_url),
            ("floating_api", floating_api),
        ):
            try:
                normalized = http_client.normalize_base_url(
                    value,
                    allow_http=allow_insecure_http,
                    label=f"{label} de {name}",
                )
            except http_client.HttpClientError as exc:
                raise ConfigError(str(exc)) from exc
            if label == "guardian_url":
                guardian_url = normalized
            else:
                floating_api = normalized
        try:
            node_ip = http_client.validate_host(node_ip, f"node_ip de {name}")
        except http_client.HttpClientError as exc:
            raise ConfigError(str(exc)) from exc
        return {
            "name": name,
            "guardian_url": guardian_url,
            "node_ip": node_ip,
            "floating_api": floating_api,
            "vaultwarden_root": vaultwarden_root,
        }

    def configure_cluster(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._configure_cluster(raw)

    def _configure_cluster(self, raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ConfigError("la configuración del grupo debe ser un objeto")
        raw_members = raw.get("members")
        if not isinstance(raw_members, list) or not 1 <= len(raw_members) <= 32:
            raise ConfigError("members debe contener entre 1 y 32 servidores")
        allow_insecure_http = raw.get(
            "allow_insecure_http",
            bool(getattr(self.settings, "allow_insecure_http", False)),
        )
        if type(allow_insecure_http) is not bool:
            raise ConfigError("allow_insecure_http debe ser true o false")
        members = [
            self._member(
                item,
                allow_insecure_http,
            )
            for item in raw_members
        ]
        names = [item["name"] for item in members]
        if len(names) != len(set(names)):
            raise ConfigError("hay nombres de servidor repetidos")
        local_name = str(raw.get("local_name", "")).strip()
        if local_name not in names:
            raise ConfigError("local_name debe identificar este servidor")
        policy_raw = dict(raw.get("policy") or {})
        policy_raw["confirm_active"] = raw.get("confirm_active") is True
        policy, confirm_active = self._validate_policy(policy_raw)
        if len(members) > 1 and not self.settings.replication_token:
            raise ReplicationError("falta la contraseña entre Guardian")

        member_urls = {item["name"]: item["guardian_url"] for item in members}
        settings_by_name = {}
        for member in members:
            settings_by_name[member["name"]] = {
                "node": member["name"],
                "node_ip": member["node_ip"],
                "peers": {
                    name: url for name, url in member_urls.items()
                    if name != member["name"]
                },
                "floating_api": member["floating_api"],
                "vaultwarden_root": member["vaultwarden_root"],
                "allow_insecure_http": allow_insecure_http,
                **policy,
            }
        self._validate_full_settings(settings_by_name[local_name], confirm_active)

        remote_members = [item for item in members if item["name"] != local_name]
        validated = {}
        for member in remote_members:
            payload = {
                "settings": settings_by_name[member["name"]],
                "confirm_active": confirm_active,
                "apply": False,
            }
            validated[member["name"]] = self._send_peer_json(
                member["name"], member["guardian_url"],
                "/api/v1/internal/settings", payload, method="PUT"
            )
        applied = {}
        for member in remote_members:
            payload = {
                "settings": settings_by_name[member["name"]],
                "confirm_active": confirm_active,
                "apply": True,
            }
            applied[member["name"]] = self._send_peer_json(
                member["name"], member["guardian_url"],
                "/api/v1/internal/settings", payload, method="PUT"
            )
        local = self.internal_settings({
            "settings": settings_by_name[local_name],
            "confirm_active": confirm_active,
            "apply": True,
        })
        reconciliation = self.reconcile_cluster({"confirm": True})
        return {
            "estado": "grupo_configurado",
            "nodos": len(members),
            "validacion": validated,
            "aplicacion": applied,
            "local": local,
            "reconciliacion": reconciliation,
        }

    @staticmethod
    def _reconciliation_transaction(instance_id: str, target: str) -> str:
        digest = hashlib.sha256(
            f"{instance_id}\0{target}".encode("utf-8")
        ).hexdigest()
        return f"backfill-{digest[:40]}"

    def _reconciliation_plan(self) -> tuple[dict, list[dict]]:
        view = self.cluster_status()
        unreachable = sorted(
            str(node.get("name") or "desconocido")
            for node in view.get("nodes") or []
            if not node.get("reachable")
        )
        if unreachable:
            raise ReplicationError(
                "no se pueden completar réplicas con servidores inaccesibles: "
                + ", ".join(unreachable)
            )
        if view.get("state") == "conflict":
            raise ReplicationError(
                "hay un conflicto de datos; resuélvelo antes de incorporar réplicas"
            )
        expected = {self.settings.node, *self.settings.peers}
        jobs = []
        for aggregate in view.get("instances") or []:
            identifier = str(aggregate.get("id") or "")
            if not identifier:
                continue
            present = set()
            for node in view.get("nodes") or []:
                if any(
                    str(item.get("id") or "") == identifier
                    for item in (node.get("status") or {}).get("instancias") or []
                ):
                    present.add(str(node.get("name") or ""))
            missing = sorted(expected - present)
            if not missing:
                continue
            porter = str(aggregate.get("porter") or "")
            if not porter or porter not in present:
                raise ReplicationError(
                    f"{identifier}: floating-IP no confirma una fuente portadora"
                )
            for target in missing:
                jobs.append({
                    "instance": identifier,
                    "porter": porter,
                    "target": target,
                    "transaction": self._reconciliation_transaction(
                        identifier, target),
                })
        return view, jobs

    def reconcile_cluster(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._reconcile_cluster(raw)

    def _reconcile_cluster(self, raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ConfigError("la reconciliación debe ser un objeto")
        unknown = sorted(set(raw) - {"confirm"})
        if unknown:
            raise ConfigError(
                "campos de reconciliación no permitidos: " + ", ".join(unknown)
            )
        if raw.get("confirm") is not True:
            raise ConfigError("completar réplicas requiere confirm=true")
        if self.settings.peers and not self.settings.replication_token:
            raise ReplicationError("falta la contraseña entre Guardian")

        initial, jobs = self._reconciliation_plan()
        if not jobs:
            return {
                "estado": "sin_cambios",
                "trabajos": [],
                "replicas_creadas": 0,
                "cluster_state": initial.get("state"),
            }
        if self.settings.mode != "active":
            return {
                "estado": "pendiente_modo_activo",
                "trabajos": jobs,
                "replicas_creadas": 0,
                "cluster_state": initial.get("state"),
            }

        results = []
        by_instance: dict[str, list[dict]] = {}
        for job in jobs:
            by_instance.setdefault(job["instance"], []).append(job)
        for identifier, instance_jobs in by_instance.items():
            porter = instance_jobs[0]["porter"]
            for job in instance_jobs:
                payload = {
                    "instance_id": identifier,
                    "target": job["target"],
                    "transaction": job["transaction"],
                }
                if porter == self.settings.node:
                    result = self.internal_reconcile_instance(payload)
                else:
                    base_url = self.settings.peers.get(porter)
                    if not base_url:
                        raise ReplicationError(
                            f"el portador {porter} no pertenece al grupo")
                    result = self._send_peer_json(
                        porter,
                        base_url,
                        "/api/v1/internal/reconciliation",
                        payload,
                        timeout=900,
                    )
                results.append({
                    "instance": identifier,
                    "porter": porter,
                    "target": job["target"],
                    "transaction": job["transaction"],
                    "resultado": result,
                })

            if porter == self.settings.node:
                sync_result = self.sync(
                    identifier,
                    context={
                        "instance": identifier,
                        "ejecutado_por": porter,
                        "solicitado_desde": self.settings.node,
                        "motivo": "incorporacion_de_servidor",
                    },
                )
            else:
                sync_result = self._send_peer_json(
                    porter,
                    self.settings.peers[porter],
                    f"/api/v1/internal/sync/{identifier}",
                    {
                        "solicitado_desde": self.settings.node,
                        "motivo": "incorporacion_de_servidor",
                    },
                    timeout=900,
                )
            for item in results:
                if item["instance"] == identifier:
                    item["sincronizacion_final"] = sync_result

        final = self.cluster_status()
        return {
            "estado": (
                "reconciliado"
                if final.get("state") == "protected"
                else "reconciliacion_parcial"
            ),
            "trabajos": results,
            "replicas_creadas": len(results),
            "instancias": sorted(by_instance),
            "nodos_incorporados": sorted({
                item["target"] for item in results
            }),
            "cluster_state": final.get("state"),
        }

    @staticmethod
    def _reconciliation_public(record: dict) -> dict:
        return {
            "transaction": record.get("transaction"),
            "stage": record.get("stage"),
            "instance": (record.get("instance") or {}).get("id"),
            "source_node": record.get("source_node"),
            "target_node": record.get("target_node"),
            "complete": record.get("stage") == "complete",
            "error": record.get("error"),
            "failed_at": record.get("failed_at"),
        }

    def internal_reconcile_instance(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._internal_reconcile_instance(raw)

    def _internal_reconcile_instance(self, raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ConfigError("la reconciliación interna debe ser un objeto")
        unknown = sorted(
            set(raw) - {"instance_id", "target", "transaction"})
        if unknown:
            raise ConfigError(
                "campos internos no permitidos: " + ", ".join(unknown))
        identifier = str(raw.get("instance_id") or "")
        target = str(raw.get("target") or "")
        transaction = str(raw.get("transaction") or "")
        if not _PROVISION_TRANSACTION.fullmatch(transaction):
            raise ConfigError("transacción de reconciliación no válida")
        if target == self.settings.node or target not in self.settings.peers:
            raise ConfigError("el destino no es otro miembro del grupo")

        instance = self.instance(identifier)
        state = self.floating_state(instance)
        if not state.known or state.portador != self.settings.node:
            raise ReplicationError(
                "sólo el portador actual de la IP puede sembrar una réplica")
        if state.local_healthy is not True:
            raise ReplicationError(
                "floating-IP no confirma saludable al portador actual")
        self._source_health(instance)

        inspected = self.docker.inspect_full(instance.container)
        if not inspected:
            raise ReplicationError("no existe el contenedor de origen")
        image = self.docker.inspect_image(str(inspected.get("Image") or ""))
        try:
            source = provisioning.normalize(inspected, image)
        except provisioning.ProvisioningError as exc:
            raise ReplicationError(str(exc)) from exc
        if not source.running:
            raise ReplicationError("el Vaultwarden de origen debe estar en marcha")
        if source.host_port != instance.health_port:
            raise ReplicationError(
                "el puerto publicado no coincide con la instancia protegida")

        private_request = {
            "transaction": transaction,
            "source": source.private(),
            "instance_id": instance.id,
            "display_name": instance.display_name,
            "data_directory": source.container,
            "health_path": instance.health_path,
            "include_sends": instance.include_sends,
            "source_node": self.settings.node,
        }
        request_hash = hashlib.sha256(json.dumps(
            private_request, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        store = self._state_store()
        existing = store.provisioning(transaction)
        if existing:
            if (
                existing.get("role") != "reconciliation"
                or existing.get("request_hash") != request_hash
                or existing.get("target_node") != target
            ):
                raise ReplicationError(
                    "la transacción pertenece a otra reconciliación")
            if existing.get("stage") == "complete":
                return self._reconciliation_public(existing)

        base_record = {
            "role": "reconciliation",
            "request_hash": request_hash,
            "instance": instance.to_dict(),
            "source_node": self.settings.node,
            "target_node": target,
            "pinned_image": source.pinned_image,
        }
        record = existing or base_record
        current_stage = "starting"

        def remember(stage: str, **changes) -> dict:
            nonlocal record, current_stage
            current_stage = stage
            payload = {**record, **base_record, **changes, "stage": stage}
            payload.pop("error", None)
            payload.pop("failed_at", None)
            record = store.remember_provisioning(transaction, payload)
            return record

        try:
            remember("starting")
            with self._lock:
                base_url = self.settings.peers[target]
                envelope = sealed.seal(
                    private_request,
                    self.settings.replication_token,
                    "provisioning-spec",
                )
                target_result = self._send_peer_json(
                    target,
                    base_url,
                    "/api/v1/internal/provisioning/preflight",
                    envelope,
                    timeout=30,
                )
                remember("validated", target=target_result)

                package_dir = (
                    self.settings.state_dir / "reconciliation-packages")
                package_dir.mkdir(parents=True, exist_ok=True)
                package = package_dir / f"{transaction}.vgb"
                if package.is_file():
                    payload = _read_package_file(
                        package, self.settings.max_package_bytes)
                    manifest, _ = snapshot.read_manifest(
                        payload,
                        self.settings.replication_token,
                        self.settings.max_package_bytes,
                    )
                else:
                    temporary = package.with_name(
                        f".{package.name}.{os.getpid()}.new")
                    try:
                        info = self._data_access().create_snapshot(
                            instance,
                            self.settings.node,
                            self.settings.replication_token,
                            temporary,
                            self.settings.max_package_bytes,
                        )
                        manifest = info["manifest"]
                        os.replace(temporary, package)
                    finally:
                        temporary.unlink(missing_ok=True)
                    payload = _read_package_file(
                        package, self.settings.max_package_bytes)
                if (
                    manifest.get("instance") != instance.id
                    or manifest.get("source_node") != self.settings.node
                ):
                    raise ReplicationError(
                        "la instantánea no corresponde a esta reconciliación")
                remember(
                    "snapshot_ready",
                    package_sha256=hashlib.sha256(payload).hexdigest(),
                    package_bytes=len(payload),
                )

                target_result = self._send_peer_json(
                    target,
                    base_url,
                    "/api/v1/internal/provisioning/prepare",
                    envelope,
                    timeout=360,
                )
                remember("replica_prepared", target=target_result)
                target_result = self._send_peer_bytes(
                    target,
                    base_url,
                    f"/api/v1/internal/provisioning/{transaction}/snapshot",
                    payload,
                    timeout=900,
                )
                remember("data_applied", target=target_result)
                target_result = self._send_peer_json(
                    target,
                    base_url,
                    f"/api/v1/internal/provisioning/{transaction}/activate",
                    {},
                    timeout=180,
                )
                complete = remember("complete", target=target_result)
                return self._reconciliation_public(complete)
        except (
            ConfigError,
            ReplicationError,
            docker_api.DockerError,
            floating.FloatingError,
            provisioning.ProvisioningError,
            sealed.SealedError,
            snapshot.SnapshotError,
            OSError,
        ) as exc:
            store.remember_provisioning(transaction, {
                **record,
                **base_record,
                "stage": "failed",
                "failed_at": current_stage,
                "error": str(exc)[:500],
            })
            if isinstance(exc, (ConfigError, ReplicationError)):
                raise
            raise ReplicationError(str(exc)) from exc

    def instance_readiness(self, instance_id: str) -> dict:
        instance = self.instance(instance_id)
        local_status = self.status()
        item = next(
            value for value in local_status["instancias"]
            if value["id"] == instance.id
        )
        try:
            inspected = self.docker.inspect(instance.container)
            running = bool(inspected.get("existe") and inspected.get("en_marcha"))
            container_detail = {
                "exists": bool(inspected.get("existe")),
                "running": bool(inspected.get("en_marcha")),
            }
        except docker_api.DockerError as exc:
            running = False
            container_detail = {"exists": False, "running": False, "error": str(exc)}
        result = readiness.evaluate(
            self.settings.node,
            item,
            cluster.collect_cluster(
                local_status,
                self.settings.peers,
                self.settings.replication_token,
                bool(getattr(self.settings, "allow_insecure_http", False)),
                getattr(self.settings, "ca_file", None),
            ),
            running,
            self.settings.interval_seconds,
        )
        result["container"] = container_detail
        return result

    def discovery(self) -> dict:
        directories = []
        for root in self.settings.data_roots:
            try:
                if not root.is_dir():
                    continue
                children = sorted(root.iterdir(), key=lambda item: item.name.lower())
            except OSError:
                continue
            for child in children[:200]:
                try:
                    if not child.is_dir() or child.is_symlink():
                        continue
                    has_sqlite = (child / "db.sqlite3").is_file()
                except OSError:
                    # La raíz puede contener datos de otras aplicaciones con
                    # permisos deliberadamente restrictivos. No son candidatos de
                    # Vaultwarden y nunca deben inutilizar el descubrimiento.
                    continue
                directories.append({
                    "path": str(child),
                    "nombre": child.name,
                    "tiene_sqlite": has_sqlite,
                })
        return {"raices": [str(root) for root in self.settings.data_roots],
                "directorios": directories}

    def provisioning_candidates(self) -> dict:
        """Inventario local; no devuelve nunca valores del entorno."""
        items = []
        for summary in self.docker.containers():
            names = summary.get("Names") or []
            name = str(names[0]).lstrip("/") if names else str(summary.get("Id") or "")
            if not name:
                continue
            inspected = self.docker.inspect_full(name)
            if not inspected:
                continue
            configured_image = str((inspected.get("Config") or {}).get("Image") or "")
            if "vaultwarden/server" not in configured_image.lower():
                continue
            image = self.docker.inspect_image(str(inspected.get("Image") or ""))
            result = provisioning.candidate(inspected, image)
            if result.get("vaultwarden"):
                items.append(result)
        items.sort(key=lambda item: str(item.get("container", "")).lower())
        return {
            "node": self.settings.node,
            "items": items,
            "secrets_exposed": False,
        }

    def internal_provisioning_preflight(self, envelope: dict) -> dict:
        try:
            with self._lock:
                return self._local_provisioner().preflight(envelope)
        except provisioning_local.LocalProvisioningError as exc:
            raise ReplicationError(str(exc)) from exc

    def internal_provisioning_prepare(self, envelope: dict) -> dict:
        try:
            with self._lock:
                return self._local_provisioner().prepare(envelope)
        except provisioning_local.LocalProvisioningError as exc:
            raise ReplicationError(str(exc)) from exc

    def internal_provisioning_snapshot(
        self, transaction: str, payload: bytes
    ) -> dict:
        try:
            with self._lock:
                manifest, _ = snapshot.read_manifest(
                    payload,
                    self.settings.replication_token,
                    self.settings.max_package_bytes,
                )
                result = self._local_provisioner().apply_snapshot(
                    transaction, payload)
                fingerprint = self._content_fingerprint(manifest)
                self._state_store().remember_content(
                    manifest["instance"], fingerprint,
                    manifest["source_node"], "provisioned",
                    confirmed_fingerprint=fingerprint,
                )
                result["fingerprint"] = fingerprint
                return result
        except (provisioning_local.LocalProvisioningError,
                snapshot.SnapshotError) as exc:
            raise ReplicationError(str(exc)) from exc

    def internal_provisioning_activate(self, transaction: str) -> dict:
        try:
            with self._lock:
                provisioner = self._local_provisioner()
                result = provisioner.activate(transaction)
                instance_raw = result.pop("instance_config")
                candidate = Instance.from_dict(instance_raw)
                existing = next(
                    (item for item in self.settings.instances
                     if item.id == candidate.id),
                    None,
                )
                if existing is None:
                    self.upsert_instance(instance_raw)
                elif existing.to_dict() != candidate.to_dict():
                    raise ReplicationError(
                        "el id ya está registrado con otra configuración")
                return provisioner.mark_registered(transaction)
        except provisioning_local.LocalProvisioningError as exc:
            raise ReplicationError(str(exc)) from exc

    def provisioning_transaction(self, transaction: str) -> dict:
        try:
            record = self._state_store().provisioning(transaction)
        except ValueError as exc:
            raise ReplicationError(str(exc)) from exc
        if not record:
            raise ReplicationError("transacción de provisión desconocida")
        if record.get("role") == "coordinator":
            return self._provisioning_public(record)
        return provisioning_local.LocalProvisioner._public(record)

    @staticmethod
    def _provisioning_public(record: dict) -> dict:
        instance = record.get("instance") or {}
        return {
            "transaction": record.get("transaction"),
            "stage": record.get("stage"),
            "instance": instance.get("id"),
            "display_name": instance.get("display_name"),
            "source_node": record.get("source_node"),
            "nodes": record.get("nodes") or {},
            "floating_ip": record.get("floating_ip"),
            "complete": record.get("stage") == "complete",
            "error": record.get("error"),
            "failed_at": record.get("failed_at"),
        }

    def _source_health(self, instance: Instance) -> None:
        try:
            origin = http_client.origin_for_host(
                self.settings.node_ip,
                instance.health_port,
                # Uncredentialed Vaultwarden health probe on the configured node.
                allow_http=True,
                label="node_ip",
            )
            http_client.request(
                origin,
                instance.health_path,
                timeout=3,
                max_bytes=64 * 1024,
                allow_http=True,
            )
            healthy = True
        except http_client.HttpClientError as exc:
            raise ReplicationError(
                "el Vaultwarden de origen no supera la comprobación de salud"
            ) from exc
        if not healthy:
            raise ReplicationError(
                "el Vaultwarden de origen no supera la comprobación de salud")

    def provision_vaultwarden(
        self, raw: dict, transaction: str
    ) -> dict:
        with self._operation_lock():
            return self._provision_vaultwarden(raw, transaction)

    def _provision_vaultwarden(
        self, raw: dict, transaction: str
    ) -> dict:
        """Clona desde este nodo y reclama la VIP sólo al final."""
        if not isinstance(raw, dict):
            raise ConfigError("la provisión debe ser un objeto")
        unknown = sorted(set(raw) - _PROVISION_FIELDS)
        if unknown:
            raise ConfigError(
                "campos de provisión no permitidos: " + ", ".join(unknown))
        if raw.get("confirm") is not True:
            raise ConfigError("crear las réplicas requiere confirm=true")
        if not _PROVISION_TRANSACTION.fullmatch(transaction or ""):
            raise ConfigError("falta una Idempotency-Key válida")
        if self.settings.mode != "active":
            raise ReplicationError(
                "activa primero la protección del grupo para mantener las réplicas")
        if not self.settings.replication_token:
            raise ReplicationError(
                "falta la contraseña entre Guardian para cifrar los datos")

        source_name = str(raw.get("source_container") or "")
        inspected = self.docker.inspect_full(source_name)
        if not inspected:
            raise ConfigError("no existe el contenedor de origen")
        image = self.docker.inspect_image(str(inspected.get("Image") or ""))
        try:
            source = provisioning.normalize(inspected, image)
        except provisioning.ProvisioningError as exc:
            raise ConfigError(str(exc)) from exc
        if not source.running:
            raise ConfigError("el Vaultwarden de origen debe estar en marcha")

        identifier = str(raw.get("instance_id") or "")
        display_name = str(raw.get("display_name") or identifier)
        data_directory = str(
            raw.get("data_directory") or source.container)
        health_path = str(raw.get("health_path") or "/alive")
        include_sends = raw.get("include_sends", True) is not False
        source_instance = Instance.from_dict({
            "id": identifier,
            "display_name": display_name,
            "container": source.container,
            "data_dir": str(
                self.settings.data_roots[0] / ".docker" / identifier),
            "data_backend": "docker",
            "health_port": source.host_port,
            "health_path": health_path,
            "floating_service": identifier,
            "include_sends": include_sends,
            "replication_enabled": True,
        })
        for current in self.settings.instances:
            if current.id == source_instance.id:
                if current.to_dict() != source_instance.to_dict():
                    raise ConfigError(
                        "el id ya está registrado con otra configuración")
                continue
            if current.container == source_instance.container:
                raise ConfigError(
                    "el contenedor de origen ya pertenece a otra instancia")
            if current.floating_service == source_instance.floating_service:
                raise ConfigError(
                    "el servicio flotante ya pertenece a otra instancia")

        peers = dict(self.settings.peers)
        raw_destinations = raw.get("destination_paths")
        if peers and not isinstance(raw_destinations, dict):
            raise ConfigError(
                "indica la ruta host completa para cada servidor de destino")
        raw_destinations = raw_destinations or {}
        if not isinstance(raw_destinations, dict):
            raise ConfigError("destination_paths debe ser un objeto")
        unknown_destinations = sorted(set(raw_destinations) - set(peers))
        missing_destinations = sorted(set(peers) - set(raw_destinations))
        if unknown_destinations:
            raise ConfigError(
                "hay rutas para servidores ajenos al grupo: "
                + ", ".join(unknown_destinations))
        if missing_destinations:
            raise ConfigError(
                "falta la ruta host de destino en: "
                + ", ".join(missing_destinations))
        try:
            destination_paths = {
                peer: provisioning.exact_target_data_path(
                    str(raw_destinations[peer]))
                for peer in sorted(peers)
            }
        except provisioning.ProvisioningError as exc:
            raise ConfigError(str(exc)) from exc

        private_request = {
            "transaction": transaction,
            "source": source.private(),
            "instance_id": source_instance.id,
            "display_name": source_instance.display_name,
            "data_directory": data_directory,
            "health_path": source_instance.health_path,
            "include_sends": source_instance.include_sends,
            "source_node": self.settings.node,
        }
        request_hash = hashlib.sha256(json.dumps(
            {**private_request, "destination_paths": destination_paths},
            ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        store = self._state_store()
        existing_record = store.provisioning(transaction)
        if existing_record:
            if (
                existing_record.get("role") != "coordinator"
                or existing_record.get("request_hash") != request_hash
            ):
                raise ReplicationError(
                    "la Idempotency-Key ya se usó para otra provisión")
            if existing_record.get("stage") == "complete":
                return self._provisioning_public(existing_record)

        base_record = {
            "role": "coordinator",
            "request_hash": request_hash,
            "instance": source_instance.to_dict(),
            "container": source.container,
            "host_port": source.host_port,
            "pinned_image": source.pinned_image,
            "source_node": self.settings.node,
            "destination_paths": destination_paths,
            "nodes": (
                existing_record.get("nodes") if existing_record else {}
            ) or {},
        }
        record = existing_record or base_record
        current_stage = "starting"

        def remember(stage: str, **changes) -> dict:
            nonlocal record, current_stage
            current_stage = stage
            payload = {**record, **base_record, **changes, "stage": stage}
            payload.pop("error", None)
            payload.pop("failed_at", None)
            record = store.remember_provisioning(transaction, payload)
            return record

        try:
            remember("starting")
            with self._lock:
                current_stage = "validating"
                self._source_health(source_instance)
                envelopes = {
                    peer: sealed.seal(
                        {
                            **private_request,
                            "target_path": destination_paths[peer],
                        },
                        self.settings.replication_token,
                        "provisioning-spec",
                    )
                    for peer in peers
                }
                nodes = {
                    self.settings.node: {
                        "stage": "source_validated",
                        "container": source.container,
                    },
                }
                for peer, base_url in peers.items():
                    nodes[peer] = self._send_peer_json(
                        peer,
                        base_url,
                        "/api/v1/internal/provisioning/preflight",
                        envelopes[peer],
                        timeout=30,
                    )
                remember("validated", nodes=nodes)

                package_dir = (
                    self.settings.state_dir / "provisioning-packages")
                package_dir.mkdir(parents=True, exist_ok=True)
                package = package_dir / f"{transaction}.vgb"
                if package.is_file():
                    payload = _read_package_file(
                        package, self.settings.max_package_bytes)
                    manifest, _ = snapshot.read_manifest(
                        payload,
                        self.settings.replication_token,
                        self.settings.max_package_bytes,
                    )
                else:
                    temporary = package.with_name(
                        f".{package.name}.{os.getpid()}.new")
                    try:
                        info = self._data_access().create_snapshot(
                            source_instance,
                            self.settings.node,
                            self.settings.replication_token,
                            temporary,
                            self.settings.max_package_bytes,
                        )
                        manifest = info["manifest"]
                        os.replace(temporary, package)
                    finally:
                        temporary.unlink(missing_ok=True)
                    payload = _read_package_file(
                        package, self.settings.max_package_bytes)
                if (
                    manifest.get("instance") != source_instance.id
                    or manifest.get("source_node") != self.settings.node
                ):
                    raise ReplicationError(
                        "la instantánea persistida no corresponde a la provisión")
                remember(
                    "snapshot_ready",
                    package_sha256=hashlib.sha256(payload).hexdigest(),
                    package_bytes=len(payload),
                )

                for peer, base_url in peers.items():
                    nodes[peer] = self._send_peer_json(
                        peer,
                        base_url,
                        "/api/v1/internal/provisioning/prepare",
                        envelopes[peer],
                        timeout=360,
                    )
                remember("replicas_prepared", nodes=nodes)

                for peer, base_url in peers.items():
                    nodes[peer] = self._send_peer_bytes(
                        peer,
                        base_url,
                        f"/api/v1/internal/provisioning/"
                        f"{transaction}/snapshot",
                        payload,
                    )
                remember("data_applied", nodes=nodes)

                for peer, base_url in peers.items():
                    nodes[peer] = self._send_peer_json(
                        peer,
                        base_url,
                        f"/api/v1/internal/provisioning/"
                        f"{transaction}/activate",
                        {},
                        timeout=180,
                    )
                remember("replicas_ready", nodes=nodes)

                existing = next(
                    (item for item in self.settings.instances
                     if item.id == source_instance.id),
                    None,
                )
                if existing is None:
                    self.upsert_instance(source_instance.to_dict())
                elif existing.to_dict() != source_instance.to_dict():
                    raise ReplicationError(
                        "la instancia local cambió durante la provisión")
                fingerprint = self._content_fingerprint(manifest)
                self._state_store().remember_content(
                    source_instance.id,
                    fingerprint,
                    self.settings.node,
                    "provisioned-source",
                    confirmed_fingerprint=fingerprint,
                )
                nodes[self.settings.node]["stage"] = "registered"
                remember("source_registered", nodes=nodes)

                claim = floating.claim(
                    self.settings.floating_api,
                    idempotency_key=transaction,
                    api_token=getattr(
                        self.settings, "floating_api_token", ""),
                    service=source_instance.floating_service,
                    description=source_instance.display_name,
                    ports=[source_instance.health_port],
                    health_port=source_instance.health_port,
                    health_path=source_instance.health_path,
                    allow_insecure_http=bool(
                        getattr(self.settings, "allow_insecure_http", False)),
                    ca_file=getattr(self.settings, "ca_file", None),
                )
                floating_result = {
                    "ip": claim["ip"],
                    "converged": claim["converged"],
                    "repeated": claim["repeated"],
                }
                if not claim["converged"]:
                    remember(
                        "floating_partial",
                        nodes=nodes,
                        floating_ip=floating_result,
                    )
                    raise ReplicationError(
                        "la IP se reservó pero aún no converge en todos los nodos")
                completed = remember(
                    "complete",
                    nodes=nodes,
                    floating_ip=floating_result,
                )
                return self._provisioning_public(completed)
        except (
            ConfigError,
            ReplicationError,
            docker_api.DockerError,
            floating.FloatingError,
            sealed.SealedError,
            snapshot.SnapshotError,
            OSError,
        ) as exc:
            failed = {
                **record,
                **base_record,
                "stage": "failed",
                "failed_at": current_stage,
                "error": str(exc)[:500],
            }
            store.remember_provisioning(transaction, failed)
            if isinstance(exc, (ConfigError, ReplicationError)):
                raise
            raise ReplicationError(str(exc)) from exc


    def _backup_directory(self, instance: Instance) -> Path:
        directory = self.settings.state_dir / "backups" / instance.id
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _new_backup_path(self, instance: Instance) -> Path:
        directory = self._backup_directory(instance)
        stem = f"antes-{time.strftime('%Y%m%d-%H%M%S')}"
        candidate = directory / f"{stem}.vgb"
        suffix = 1
        while candidate.exists():
            candidate = directory / f"{stem}-{suffix}.vgb"
            suffix += 1
        return candidate

    def _backup_files(self, instance: Instance) -> list[Path]:
        directory = self._backup_directory(instance)
        files = [path for path in directory.glob("antes-*.vgb")
                 if path.is_file() and _BACKUP_NAME.fullmatch(path.name)]
        return sorted(files, key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True)

    def _prune_backups(self, instance: Instance, preserve: set[str] | None = None) -> int:
        preserve = preserve or set()
        files = self._backup_files(instance)
        retained = [path for path in files if path.name in preserve]
        candidates = [path for path in files if path.name not in preserve]
        for path in candidates[self.settings.backup_retention:]:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        return len(retained) + min(len(candidates), self.settings.backup_retention)

    def _apply_with_safety_backup(
        self,
        instance: Instance,
        payload: bytes,
        safety_backup: Path,
    ) -> dict:
        access = self._data_access()
        try:
            return access.apply_snapshot(
                instance,
                payload,
                self.settings.replication_token,
                self.settings.max_package_bytes,
            )
        except (OSError, snapshot.SnapshotError) as primary:
            try:
                previous = _read_package_file(
                    safety_backup, self.settings.max_package_bytes)
                access.apply_snapshot(
                    instance,
                    previous,
                    self.settings.replication_token,
                    self.settings.max_package_bytes,
                )
            except (OSError, snapshot.SnapshotError) as rollback:
                raise ReplicationError(
                    "falló la aplicación y también el rollback automático: "
                    f"aplicación={primary}; rollback={rollback}"
                ) from rollback
            raise ReplicationError(
                "falló la aplicación; el backup de seguridad se restauró "
                f"automáticamente: {primary}"
            ) from primary

    def backups(self, instance_id: str) -> dict:
        instance = self.instance(instance_id)
        items = []
        for path in self._backup_files(instance):
            stat = path.stat()
            items.append({
                "nombre": path.name,
                "bytes": stat.st_size,
                "modificado": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime(stat.st_mtime)),
            })
        return {
            "instancia": instance.id,
            "retencion": self.settings.backup_retention,
            "items": items,
        }

    def metrics(self) -> str:
        status = self.status()
        lines = [
            "# HELP vault_guardian_info Información estática del nodo.",
            "# TYPE vault_guardian_info gauge",
            f'vault_guardian_info{{node="{self.settings.node}",mode="{self.settings.mode}"}} 1',
            "# HELP vault_guardian_backup_retention Número máximo de backups conservados.",
            "# TYPE vault_guardian_backup_retention gauge",
            f'vault_guardian_backup_retention{{node="{self.settings.node}"}} {self.settings.backup_retention}',
            "# HELP vault_guardian_instance_configured Instancia declarada en el estado.",
            "# TYPE vault_guardian_instance_configured gauge",
            "# HELP vault_guardian_instance_replication_enabled Puerta de replicación.",
            "# TYPE vault_guardian_instance_replication_enabled gauge",
            "# HELP vault_guardian_instance_floating_known Estado conocido de la VIP.",
            "# TYPE vault_guardian_instance_floating_known gauge",
            "# HELP vault_guardian_instance_active Este nodo sostiene la VIP.",
            "# TYPE vault_guardian_instance_active gauge",
            "# HELP vault_guardian_instance_health Salud local declarada por floating-ip.",
            "# TYPE vault_guardian_instance_health gauge",
            "# HELP vault_guardian_backup_count Backups locales disponibles.",
            "# TYPE vault_guardian_backup_count gauge",
            "# HELP vault_guardian_last_sync Último estado de sincronización conocido.",
            "# TYPE vault_guardian_last_sync gauge",
        ]
        for item in status["instancias"]:
            instance = item["id"]
            labels = f'node="{self.settings.node}",instance="{instance}"'
            floating_state = item.get("floating_ip") or {}
            last = item.get("último_resultado") or {}
            backups = self.backups(item["id"])
            lines.extend([
                f"vault_guardian_instance_configured{{{labels}}} 1",
                f"vault_guardian_instance_replication_enabled{{{labels}}} {int(item['replicacion'])}",
                f"vault_guardian_instance_floating_known{{{labels}}} {int(bool(floating_state.get('conocido')))}",
                f"vault_guardian_instance_active{{{labels}}} {int(floating_state.get('portador') == self.settings.node)}",
                f"vault_guardian_instance_health{{{labels}}} {int(floating_state.get('salud_local') is True)}",
                f"vault_guardian_backup_count{{{labels}}} {len(backups['items'])}",
            ])
            if last.get("estado"):
                state = str(last["estado"])
                lines.append(f'vault_guardian_last_sync{{{labels},state="{state}"}} 1')
        return "\n".join(lines) + "\n"

    def _candidate_is_usable(self, candidate: Instance) -> None:
        try:
            inside = any(os.path.commonpath((str(root), str(candidate.data_dir))) == str(root)
                         for root in self.settings.data_roots)
        except ValueError:
            inside = False
        if not inside:
            raise ConfigError(
                f"data_dir queda fuera de las raíces montadas: {candidate.data_dir}"
            )
        try:
            self._data_access().backend(candidate)
        except data_access.DataAccessError as exc:
            raise ConfigError(str(exc)) from exc

    def _instance_change(self, raw: dict, existing_id: str | None = None) -> list[Instance]:
        candidate = Instance.from_dict(raw)
        if existing_id is not None and candidate.id != existing_id:
            raise ConfigError("el id no puede cambiarse durante una edición")
        self._candidate_is_usable(candidate)
        current = list(self.settings.instances)
        if existing_id is None:
            if any(item.id == candidate.id for item in current):
                raise ConfigError(f"ya existe la instancia {candidate.id!r}")
            current.append(candidate)
        else:
            for index, item in enumerate(current):
                if item.id == existing_id:
                    current[index] = candidate
                    break
            else:
                raise ConfigError(f"no existe la instancia {existing_id!r}")
        return current

    def upsert_instance(self, raw: dict, existing_id: str | None = None) -> dict:
        with self._operation_lock():
            return self._upsert_instance(raw, existing_id)

    def _upsert_instance(self, raw: dict, existing_id: str | None = None) -> dict:
        current = self._instance_change(raw, existing_id)
        write_instances(self.settings.instances_file, current)
        self.settings = Settings.load(self.settings.instances_file)
        return self.config()

    def delete_instance(self, instance_id: str) -> dict:
        with self._operation_lock():
            return self._delete_instance(instance_id)

    def _delete_instance(self, instance_id: str) -> dict:
        current = [item for item in self.settings.instances if item.id != instance_id]
        if len(current) == len(self.settings.instances):
            raise ConfigError(f"no existe la instancia {instance_id!r}")
        write_instances(self.settings.instances_file, current)
        self.settings = Settings.load(self.settings.instances_file)
        return self.config()

    def internal_instance_config(self, raw: dict) -> dict:
        with self._operation_lock():
            return self._internal_instance_config(raw)

    def _internal_instance_config(self, raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ConfigError("la configuración de instancia debe ser un objeto")
        action = raw.get("action")
        apply = raw.get("apply") is True
        if action == "upsert":
            instance = raw.get("instance")
            if not isinstance(instance, dict):
                raise ConfigError("instance debe ser un objeto")
            existing_id = raw.get("existing_id")
            if existing_id is not None and not isinstance(existing_id, str):
                raise ConfigError("existing_id no es válido")
            self._instance_change(instance, existing_id)
            if apply:
                self.upsert_instance(instance, existing_id)
            identifier = str(instance.get("id", ""))
        elif action == "delete":
            identifier = str(raw.get("instance_id", ""))
            if not any(item.id == identifier for item in self.settings.instances):
                raise ConfigError(f"no existe la instancia {identifier!r}")
            if apply:
                self.delete_instance(identifier)
        else:
            raise ConfigError("action debe ser upsert o delete")
        return {
            "estado": "aplicado" if apply else "validado",
            "nodo": self.settings.node,
            "instance": identifier,
        }

    def _cluster_instance_change(self, payload: dict) -> dict:
        if self.settings.peers and not self.settings.replication_token:
            raise ReplicationError("falta la contraseña entre Guardian")
        validated = {}
        preview = {**payload, "apply": False}
        for peer, base_url in self.settings.peers.items():
            validated[peer] = self._send_peer_json(
                peer, base_url, "/api/v1/internal/instance-config",
                preview, method="PUT",
            )
        applied = {}
        change = {**payload, "apply": True}
        for peer, base_url in self.settings.peers.items():
            applied[peer] = self._send_peer_json(
                peer, base_url, "/api/v1/internal/instance-config",
                change, method="PUT",
            )
        local = self.internal_instance_config(change)
        return {
            "estado": "instancia_aplicada_en_grupo",
            "nodos": 1 + len(applied),
            "instance": local["instance"],
            "validacion": validated,
            "aplicacion": applied,
        }

    def upsert_instance_cluster(
        self, raw: dict, existing_id: str | None = None
    ) -> dict:
        with self._operation_lock():
            return self._upsert_instance_cluster(raw, existing_id)

    def _upsert_instance_cluster(
        self, raw: dict, existing_id: str | None = None
    ) -> dict:
        self._instance_change(raw, existing_id)
        return self._cluster_instance_change({
            "action": "upsert",
            "instance": raw,
            "existing_id": existing_id,
        })

    def delete_instance_cluster(self, instance_id: str) -> dict:
        with self._operation_lock():
            return self._delete_instance_cluster(instance_id)

    def _delete_instance_cluster(self, instance_id: str) -> dict:
        if not any(item.id == instance_id for item in self.settings.instances):
            raise ConfigError(f"no existe la instancia {instance_id!r}")
        return self._cluster_instance_change({
            "action": "delete",
            "instance_id": instance_id,
        })

    def validate_instance(self, raw: dict) -> dict:
        candidate = Instance.from_dict(raw)
        try:
            health_origin = http_client.origin_for_host(
                self.settings.node_ip,
                candidate.health_port,
                # This GET contains no token; peer and floating APIs still require TLS.
                allow_http=True,
                label="node_ip",
            )
            health_url = f"{health_origin}{candidate.health_path}"
        except http_client.HttpClientError:
            health_origin = ""
            health_url = ""
        result = {
            "id": candidate.id,
            "nombre": candidate.display_name or candidate.id,
            "data_dir": str(candidate.data_dir),
            "replicacion": {"habilitada": candidate.replication_enabled},
            "datos": {"ok": candidate.data_dir.is_dir()},
            "contenedor": {"ok": False},
            "salud": {"ok": False, "url": health_url},
            "floating_ip": {"ok": False},
            "ok": False,
        }
        try:
            self._candidate_is_usable(candidate)
            result["datos"] = {
                "ok": True,
                "backend": self._data_access().backend(candidate),
            }
        except ConfigError as exc:
            result["datos"] = {"ok": False, "detalle": str(exc)}
        try:
            inspected = self.docker.inspect(candidate.container)
            result["contenedor"] = {
                "ok": bool(inspected.get("existe")),
                "en_marcha": bool(inspected.get("en_marcha")),
            }
        except docker_api.DockerError as exc:
            result["contenedor"] = {"ok": False, "detalle": str(exc)}
        try:
            if not health_origin:
                raise http_client.HttpClientError("URL de salud no permitida")
            response = http_client.request(
                health_origin,
                candidate.health_path,
                timeout=3,
                max_bytes=64 * 1024,
                allow_http=True,
            )
            result["salud"] = {"ok": True, "status": response.status,
                               "url": health_url}
        except http_client.HttpClientError as exc:
            result["salud"] = {"ok": False, "url": result["salud"]["url"],
                               "detalle": type(exc).__name__}
        try:
            state = self.floating_state(candidate)
            result["floating_ip"] = {"ok": state.known, **state.as_dict()}
        except floating.FloatingError as exc:
            result["floating_ip"] = {"ok": False, "detalle": str(exc)}
        result["ok"] = all((
            result["datos"].get("ok"),
            result["contenedor"].get("ok"),
            result["salud"].get("ok"),
            result["floating_ip"].get("ok"),
        ))
        return result


    def restore(self, instance_id: str, backup_name: str, confirmed: bool) -> dict:
        with self._instance_operation_lock(instance_id):
            return self._restore(instance_id, backup_name, confirmed)

    def _restore(self, instance_id: str, backup_name: str, confirmed: bool) -> dict:
        if not confirmed:
            raise ConfigError("la restauración requiere confirm=true")
        if self.settings.mode != "active":
            raise ReplicationError("la restauración sólo está permitida en modo active")
        if not self.settings.replication_token:
            raise ReplicationError("falta token de replicación")
        if not isinstance(backup_name, str) or not _BACKUP_NAME.fullmatch(backup_name):
            raise ConfigError("nombre de backup no válido")
        instance = self.instance(instance_id)
        path = self._backup_directory(instance) / backup_name
        if not path.is_file():
            raise ConfigError("backup no encontrado")
        try:
            state = self.floating_state(instance)
        except floating.FloatingError as exc:
            raise ReplicationError(str(exc)) from exc
        if not state.known or not state.portador:
            raise ReplicationError("no se conoce un portador fiable")
        if state.portador == self.settings.node:
            raise ReplicationError("no se puede restaurar en el nodo que sostiene la VIP")
        payload = _read_package_file(path, self.settings.max_package_bytes)
        try:
            manifest, payload = snapshot.refresh_backup(
                payload,
                self.settings.replication_token,
                self.settings.max_package_bytes,
            )
        except snapshot.SnapshotError as exc:
            raise ReplicationError(str(exc)) from exc
        if manifest.get("instance") != instance.id:
            raise ReplicationError("el backup no corresponde a la instancia")
        inspected = self.docker.inspect(instance.container)
        if not inspected.get("existe") or not inspected.get("en_marcha"):
            raise ReplicationError("el contenedor destino no está en marcha")

        safety_backup = self._new_backup_path(instance)
        self._data_access().create_snapshot(
            instance, self.settings.node, self.settings.replication_token,
            safety_backup, self.settings.max_package_bytes)
        stopped = False
        try:
            self.docker.stop(instance.container)
            stopped = True
            result = self._apply_with_safety_backup(
                instance, payload, safety_backup)
            fingerprint = self._content_fingerprint(manifest)
            self._remember_applied(instance, fingerprint, manifest["source_node"])
            result.update({
                "estado": "restaurado",
                "backup": str(safety_backup),
                "restaurado": backup_name,
                "fingerprint": fingerprint,
            })
            self._prune_backups(instance, {backup_name})
            return self._remember(instance.id, result)
        finally:
            if stopped:
                self.docker.start(instance.container)

    def baseline(self, instance_id: str, expected_fingerprint: str | None,
                 confirmed: bool) -> dict:
        with self._instance_operation_lock(instance_id):
            return self._baseline(instance_id, expected_fingerprint, confirmed)

    def _baseline(self, instance_id: str, expected_fingerprint: str | None,
                  confirmed: bool) -> dict:
        instance = self.instance(instance_id)
        if not self.settings.replication_token:
            raise ReplicationError("falta token de replicación")
        with tempfile.TemporaryDirectory(prefix="vg-baseline-") as directory:
            package = Path(directory) / f"{instance.id}.vgb"
            try:
                info = self._data_access().create_snapshot(
                    instance,
                    self.settings.node,
                    self.settings.replication_token,
                    package,
                    self.settings.max_package_bytes,
                )
            except snapshot.SnapshotError as exc:
                raise ReplicationError(str(exc)) from exc
        fingerprint = self._content_fingerprint(info["manifest"])
        result = {
            "estado": "baseline_verificado",
            "instance": instance.id,
            "fingerprint": fingerprint,
            "persistido": False,
        }
        if not confirmed:
            return result
        if (
            not isinstance(expected_fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint)
        ):
            raise ConfigError("confirmar baseline requiere expected_fingerprint válido")
        if expected_fingerprint != fingerprint:
            raise ReplicationError("la huella local no coincide con el baseline esperado")
        known = self._state_store().content(instance.id) or {}
        ancestors = [
            value for value in [known.get("fingerprint"),
                                *(known.get("ancestor_fingerprints") or [])]
            if isinstance(value, str) and value != fingerprint
        ]
        self._state_store().remember_content(
            instance.id, fingerprint, self.settings.node, "baseline",
            parent_fingerprint=known.get("fingerprint"),
            confirmed_fingerprint=fingerprint,
            ancestor_fingerprints=ancestors,
        )
        result.update({"estado": "baseline_confirmado", "persistido": True})
        return self._remember(instance.id, result)

    def sync_selected(self, instance_id: str) -> dict:
        instance = self.instance(instance_id)
        try:
            state = self.floating_state(instance)
        except floating.FloatingError as exc:
            return self._remember(instance.id, {
                "estado": "bloqueado",
                "motivo": str(exc),
                "instance": instance.id,
            })
        if not state.known or not state.portador:
            return self._remember(instance.id, {
                "estado": "bloqueado",
                "motivo": "no se conoce el portador de la IP flotante",
                "instance": instance.id,
            })
        context = {
            "instance": instance.id,
            "ejecutado_por": state.portador,
            "solicitado_desde": self.settings.node,
        }
        if state.portador == self.settings.node:
            return self.sync(instance.id, context=context)
        else:
            base_url = self.settings.peers.get(state.portador)
            if not base_url:
                return self._remember(instance.id, {
                    "estado": "bloqueado",
                    "motivo": f"el portador {state.portador} no está en el grupo",
                    "instance": instance.id,
                })
            result = self._send_peer_json(
                state.portador, base_url,
                f"/api/v1/internal/sync/{instance.id}",
                {"solicitado_desde": self.settings.node},
                method="POST", timeout=120,
            )
        result.update(context)
        return self._remember(instance.id, result)

    def sync(self, instance_id: str, context: dict | None = None) -> dict:
        with self._instance_operation_lock(instance_id):
            return self._sync(instance_id, context)

    def _sync(self, instance_id: str, context: dict | None = None) -> dict:
        instance = self.instance(instance_id)
        def remember(result: dict) -> dict:
            if context:
                result.update(context)
            return self._remember(instance.id, result)

        if not instance.replication_enabled:
            return remember({
                "estado": "deshabilitado",
                "motivo": "replicación desactivada para esta instancia",
            })
        if self.settings.mode == "observe":
            return remember({"estado": "deshabilitado", "motivo": "modo observe"})
        if not self.settings.replication_token:
            return remember({"estado": "bloqueado", "motivo": "falta token"})
        try:
            state = self.floating_state(instance)
        except floating.FloatingError as exc:
            return remember({"estado": "bloqueado", "motivo": str(exc)})
        if not state.is_node_active(self.settings.node):
            result = {
                "estado": "en_espera",
                "motivo": "este Guardian espera al portador de la IP",
                "portador": state.portador,
            }
            return remember(result) if context else result

        with tempfile.TemporaryDirectory(prefix="vg-send-") as directory:
            package = Path(directory) / f"{instance.id}.vgb"
            known = self._state_store().content(instance.id) or {}
            parent = known.get("fingerprint")
            ancestors = ([parent] if parent else []) + list(
                known.get("ancestor_fingerprints") or []
            )
            try:
                info = self._data_access().create_snapshot(
                    instance, self.settings.node, self.settings.replication_token,
                    package, self.settings.max_package_bytes,
                    parent_fingerprint=parent,
                    ancestor_fingerprints=ancestors,
                )
            except snapshot.SnapshotError as exc:
                return remember({"estado": "error", "motivo": str(exc)})
            result = {
                "estado": "preparado",
                "bytes": info["bytes"],
                "sha256": info["sha256"],
                "pares": {},
                "fingerprint": self._content_fingerprint(info["manifest"]),
                "parent_fingerprint": parent,
            }
            if self.settings.mode == "dry-run":
                return remember(result)
            payload = _read_package_file(
                package, self.settings.max_package_bytes)
            for peer, base_url in self.settings.peers.items():
                try:
                    result["pares"][peer] = self._send(peer, base_url, instance, payload)
                except Exception as exc:  # noqa: BLE001 - se informa por par
                    result["pares"][peer] = {"ok": False, "error": str(exc)}
            successes = sum(1 for item in result["pares"].values() if item.get("ok"))
            expected = len(self.settings.peers)
            if expected == 0:
                result["estado"] = "sin_destinos"
            elif successes == expected:
                result["estado"] = "sincronizado"
            elif successes:
                result["estado"] = "degradado"
            else:
                result["estado"] = "error"
            result["destinos_ok"] = successes
            result["destinos_esperados"] = expected
            self._state_store().remember_content(
                instance.id, result["fingerprint"], self.settings.node, "source",
                parent_fingerprint=parent,
                confirmed_fingerprint=(
                    result["fingerprint"] if successes == expected and expected
                    else known.get("confirmed_fingerprint")
                ),
                ancestor_fingerprints=ancestors,
            )
            return remember(result)


    def _applied_state_path(self, instance: Instance) -> Path:
        return self.settings.state_dir / "replication" / f"{instance.id}.json"

    def _content_fingerprint(self, manifest: dict) -> str:
        entries = list(manifest.get("entries", []))
        content = {
            "instance": manifest.get("instance"),
            "include_sends": manifest.get("include_sends"),
            "entries": sorted(entries, key=lambda entry: entry.get("path", "")),
        }
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _read_applied_fingerprint(self, instance: Instance) -> str | None:
        payload = self._state_store().content(instance.id) or {}
        value = payload.get("fingerprint")
        return value if isinstance(value, str) else None

    def _remember_applied(self, instance: Instance, fingerprint: str,
                          source_node: str, parent_fingerprint: str | None = None,
                          ancestor_fingerprints: list[str] | None = None) -> None:
        self._state_store().remember_content(
            instance.id, fingerprint, source_node, "applied",
            parent_fingerprint=parent_fingerprint,
            confirmed_fingerprint=fingerprint,
            ancestor_fingerprints=ancestor_fingerprints,
        )

    @staticmethod
    def _lineage_conflict(known: dict | None, local_fingerprint: str,
                          incoming_fingerprint: str,
                          incoming_lineage: list[str]) -> str | None:
        if local_fingerprint == incoming_fingerprint:
            return None
        if not known:
            return None
        recorded = known.get("fingerprint")
        if recorded and local_fingerprint != recorded:
            return "los datos locales cambiaron fuera del linaje registrado"
        if local_fingerprint not in incoming_lineage:
            return "la réplica recibida no desciende del contenido local"
        return None

    def receive(self, instance_id: str, payload: bytes, source_node: str | None) -> dict:
        with self._instance_operation_lock(instance_id):
            return self._receive(instance_id, payload, source_node)

    def _receive(self, instance_id: str, payload: bytes,
                 source_node: str | None) -> dict:
        if self.settings.mode != "active":
            raise ReplicationError("este nodo no está en modo active")
        if not self.settings.replication_token:
            raise ReplicationError("falta token de replicación")
        instance = self.instance(instance_id)
        if not instance.replication_enabled:
            raise ReplicationError("replicación desactivada para esta instancia")
        if not source_node or source_node == self.settings.node:
            raise ReplicationError("origen de réplica no válido")
        try:
            state = self.floating_state(instance)
        except floating.FloatingError as exc:
            raise ReplicationError(str(exc)) from exc
        if not state.known or not state.portador:
            raise ReplicationError("no se conoce un portador fiable")
        if state.portador != source_node:
            raise ReplicationError("el origen ya no sostiene la VIP")
        if state.portador == self.settings.node:
            raise ReplicationError("este nodo sostiene la VIP; se rechaza la recepción")
        try:
            manifest, _ = snapshot.read_manifest(payload, self.settings.replication_token,
                                                 self.settings.max_package_bytes)
        except snapshot.SnapshotError as exc:
            raise ReplicationError(str(exc)) from exc
        if manifest.get("instance") != instance.id or manifest.get("source_node") != source_node:
            raise ReplicationError("manifest y cabeceras no coinciden")
        inspected = self.docker.inspect(instance.container)
        if not inspected.get("existe"):
            raise ReplicationError(f"no existe el contenedor permitido {instance.container!r}")
        if not inspected.get("en_marcha"):
            raise ReplicationError("el contenedor destino no está en marcha")

        backup_path = self._new_backup_path(instance)
        backup_info = self._data_access().create_snapshot(
            instance, self.settings.node, self.settings.replication_token,
            backup_path, self.settings.max_package_bytes,
        )
        local_fingerprint = self._content_fingerprint(backup_info["manifest"])
        fingerprint = self._content_fingerprint(manifest)
        lineage = []
        for value in [manifest.get("parent_fingerprint"),
                      *(manifest.get("ancestor_fingerprints") or [])]:
            if isinstance(value, str) and value and value not in lineage:
                lineage.append(value)
        conflict = self._lineage_conflict(
            self._state_store().content(instance.id),
            local_fingerprint,
            fingerprint,
            lineage,
        )
        if local_fingerprint == fingerprint:
            backup_path.unlink(missing_ok=True)
            self._remember_applied(
                instance, fingerprint, source_node,
                manifest.get("parent_fingerprint"), lineage,
            )
            return self._remember(instance.id, {
                "estado": "sin_cambios",
                "motivo": "el contenido local ya coincide",
                "fingerprint": fingerprint,
            })
        stopped = False
        try:
            self.docker.stop(instance.container)
            stopped = True
            result = self._apply_with_safety_backup(
                instance, payload, backup_path)
            self._remember_applied(
                instance, fingerprint, source_node,
                manifest.get("parent_fingerprint"), lineage,
            )
            result["estado"] = "aplicado"
            result["fingerprint"] = fingerprint
            result["backup"] = str(backup_path)
            result["sha256"] = hashlib.sha256(payload).hexdigest()
            if conflict:
                result["reconciliacion"] = {
                    "estado": "divergencia_reemplazada",
                    "motivo": conflict,
                    "autoridad": source_node,
                    "fingerprint_anterior": local_fingerprint,
                    "fingerprint_aplicado": fingerprint,
                }
            self._prune_backups(instance)
            return self._remember(instance.id, result)
        finally:
            if stopped:
                self.docker.start(instance.container)

    def _send_peer_json(
        self,
        peer: str,
        base_url: str,
        path: str,
        payload: dict,
        method: str = "POST",
        timeout: int = 15,
    ) -> dict:
        if not self.settings.replication_token:
            raise ReplicationError("falta la contraseña entre Guardian")
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            response = http_client.request(
                base_url,
                path,
                method=method,
                body=encoded,
                headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Replication-Token": self.settings.replication_token,
                "X-VG-Source-Node": self.settings.node,
                },
                timeout=timeout,
                max_bytes=1024 * 1024,
                allow_http=bool(getattr(self.settings, "allow_insecure_http", False)),
                ca_file=getattr(self.settings, "ca_file", None),
            )
            body = response.body
        except http_client.HttpStatusError as exc:
            raise ReplicationError(f"{peer} respondió HTTP {exc.status}") from exc
        except http_client.HttpClientError as exc:
            raise ReplicationError(f"no se llega a {peer}: {type(exc).__name__}") from exc
        try:
            parsed = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReplicationError(f"{peer} devolvió JSON no válido") from exc
        if not isinstance(parsed, dict):
            raise ReplicationError(f"{peer} devolvió una respuesta no válida")
        return parsed

    def _send_peer_bytes(
        self,
        peer: str,
        base_url: str,
        path: str,
        payload: bytes,
        timeout: int = 180,
    ) -> dict:
        if not self.settings.replication_token:
            raise ReplicationError("falta la contraseña entre Guardian")
        try:
            response = http_client.request(
                base_url,
                path,
                method="POST",
                body=payload,
                headers={
                "Content-Type": "application/octet-stream",
                "Accept": "application/json",
                "X-Replication-Token": self.settings.replication_token,
                "X-VG-Source-Node": self.settings.node,
                },
                timeout=timeout,
                max_bytes=1024 * 1024,
                allow_http=bool(getattr(self.settings, "allow_insecure_http", False)),
                ca_file=getattr(self.settings, "ca_file", None),
            )
            body = response.body
        except http_client.HttpStatusError as exc:
            raise ReplicationError(f"{peer} respondió HTTP {exc.status}") from exc
        except http_client.HttpClientError as exc:
            raise ReplicationError(f"no se llega a {peer}: {type(exc).__name__}") from exc
        try:
            parsed = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReplicationError(
                f"{peer} devolvió JSON no válido") from exc
        if not isinstance(parsed, dict):
            raise ReplicationError(
                f"{peer} devolvió una respuesta no válida")
        return parsed

    def _send(self, peer: str, base_url: str, instance: Instance, payload: bytes) -> dict:
        for attempt in range(3):
            try:
                response = http_client.request(
                    base_url,
                    f"/api/v1/internal/replication/{instance.id}",
                    method="POST",
                    body=payload,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-Replication-Token": self.settings.replication_token,
                        "X-VG-Source-Node": self.settings.node,
                    },
                    timeout=60,
                    max_bytes=4096,
                    allow_http=bool(getattr(self.settings, "allow_insecure_http", False)),
                    ca_file=getattr(self.settings, "ca_file", None),
                )
                parsed = json.loads(response.body.decode("utf-8")) if response.body else {}
                return {"ok": True, "respuesta": parsed}
            except http_client.HttpStatusError as exc:
                if exc.status == 503 and attempt < 2:
                    time.sleep(attempt + 1)
                    continue
                raise ReplicationError(f"{peer} respondió HTTP {exc.status}") from exc
            except http_client.HttpClientError as exc:
                raise ReplicationError(
                    f"no se llega a {peer}: {type(exc).__name__}"
                ) from exc
        raise ReplicationError(f"{peer} no aceptó la réplica tras los reintentos")

    def _remember(self, instance_id: str, result: dict) -> dict:
        try:
            event = self._state_store().remember_result(instance_id, result)
        except StateError as exc:
            raise ReplicationError("no se pudo persistir el historial local") from exc
        with self._lock:
            self._last[instance_id] = LastResult(
                at=event["at"], result=result)
        return result

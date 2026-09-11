"""Acceso seguro a los bind mounts de Vaultwarden desde el único Guardian."""

from __future__ import annotations

import socket
import stat
from dataclasses import replace
from pathlib import Path, PurePosixPath

import docker_api
import snapshot
from config import Instance


class DataAccessError(snapshot.SnapshotError):
    pass


class ContainerData:
    """Resuelve un volumen ``/data`` sin crear contenedores auxiliares.

    El host monta en Guardian una raíz autorizada bajo ``/instances``. La ruta
    efectiva nunca se acepta sólo porque exista dentro del contenedor: también
    debe corresponder exactamente con el bind mount ``/data`` que Docker declara
    para el Vaultwarden seleccionado.
    """

    def __init__(
        self,
        docker: docker_api.DockerClient,
        managed_root: str | Path = "/instances",
    ):
        self.docker = docker
        root = Path(managed_root)
        if not root.is_absolute() or str(root) == "/":
            raise DataAccessError("la raíz de datos administrada no es válida")
        self.managed_root = root.resolve()

    @staticmethod
    def _safe_host_path(value: object, label: str) -> PurePosixPath:
        raw = str(value or "")
        path = PurePosixPath(raw)
        if (
            not path.is_absolute()
            or raw in {"", "/"}
            or any(char in raw for char in ("\x00", "\r", "\n", ":"))
            or any(part in {".", ".."} for part in path.parts)
        ):
            raise DataAccessError(f"{label} no es una carpeta host segura")
        return path

    def _host_data_path(self, container: str) -> PurePosixPath:
        inspected = self.docker.inspect_full(container)
        if not inspected:
            raise DataAccessError(f"no existe el contenedor {container}")
        matches = [
            item for item in (inspected.get("Mounts") or [])
            if isinstance(item, dict) and item.get("Destination") == "/data"
        ]
        if len(matches) != 1:
            raise DataAccessError(f"{container} no tiene un único volumen /data")
        mount = matches[0]
        if mount.get("Type") != "bind" or mount.get("RW") is False:
            raise DataAccessError(
                f"{container} no usa una carpeta host escribible en /data")
        return self._safe_host_path(
            mount.get("Source"), f"el volumen /data de {container}")

    def _guardian_inspect(self) -> dict:
        hostname = socket.gethostname()
        inspected = self.docker.inspect_full(hostname)
        if inspected:
            return inspected

        candidates = []
        for item in self.docker.containers():
            labels = item.get("Labels") or {}
            if (
                isinstance(labels, dict)
                and labels.get("com.vault-guardian.role") == "app"
            ):
                identifier = str(item.get("Id") or "")
                if identifier:
                    candidates.append(identifier)
        if len(candidates) != 1:
            raise DataAccessError(
                "Docker no pudo identificar el único contenedor Vault Guardian")
        inspected = self.docker.inspect_full(candidates[0])
        if not inspected:
            raise DataAccessError("Docker no pudo inspeccionar Vault Guardian")
        return inspected

    def _managed_mounts(self) -> list[tuple[PurePosixPath, Path]]:
        inspected = self._guardian_inspect()
        matches: list[tuple[PurePosixPath, Path]] = []
        for mount in inspected.get("Mounts") or []:
            if not isinstance(mount, dict) or mount.get("Type") != "bind":
                continue
            if mount.get("RW") is False:
                continue
            destination = Path(str(mount.get("Destination") or ""))
            try:
                resolved_destination = destination.resolve()
                resolved_destination.relative_to(self.managed_root)
            except (OSError, ValueError):
                continue
            source = self._safe_host_path(
                mount.get("Source"), "la raíz de datos de Vault Guardian")
            matches.append((source, resolved_destination))
        return matches

    def mount_available(self) -> bool:
        """Confirma mediante Docker que existe una raíz de datos escribible."""
        try:
            return bool(self._managed_mounts())
        except (AttributeError, DataAccessError, docker_api.DockerError):
            return False

    def _mounted_host_target(self, host_path: str) -> Path:
        source = self._safe_host_path(host_path, "la ruta host de destino")
        candidates: list[tuple[int, Path]] = []
        for host_root, container_root in self._managed_mounts():
            try:
                relative = source.relative_to(host_root)
            except ValueError:
                continue
            if not relative.parts:
                continue
            candidate = container_root / Path(*relative.parts)
            try:
                resolved = candidate.resolve()
                resolved.relative_to(self.managed_root)
            except (OSError, ValueError):
                continue
            candidates.append((len(host_root.parts), resolved))
        if not candidates:
            raise DataAccessError(
                "la ruta host de destino queda fuera de la raíz montada "
                "en /instances")
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    def check_target_directory(self, host_path: str) -> dict:
        """Valida un destino vacío sin crearlo ni modificarlo."""
        target = self._mounted_host_target(host_path)
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            parent = target.parent
            try:
                parent_metadata = parent.lstat()
            except OSError as exc:
                raise DataAccessError(
                    "no existe la carpeta padre de la ruta de destino") from exc
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise DataAccessError(
                    "la carpeta padre de la ruta de destino no es segura")
            return {"exists": False, "empty": True, "will_create": True}
        except OSError as exc:
            raise DataAccessError(
                "no se puede inspeccionar la ruta host de destino") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DataAccessError(
                "la ruta host de destino no es una carpeta segura")
        try:
            empty = next(target.iterdir(), None) is None
        except OSError as exc:
            raise DataAccessError(
                "no se puede inspeccionar la carpeta de destino") from exc
        if not empty:
            raise DataAccessError(
                "la carpeta de destino contiene datos y no se sobrescribirá")
        return {"exists": True, "empty": True, "will_create": False}

    def prepare_target_directory(self, host_path: str) -> bool:
        """Usa una carpeta vacía o crea de forma explícita sólo la carpeta final."""
        state = self.check_target_directory(host_path)
        if state["exists"]:
            return False
        target = self._mounted_host_target(host_path)
        try:
            target.mkdir(mode=0o700)
        except OSError as exc:
            raise DataAccessError(
                "no se pudo crear la carpeta host de destino") from exc
        return True

    def discard_created_target(self, host_path: str) -> None:
        """Retira sólo una carpeta vacía creada por una preparación fallida."""
        target = self._mounted_host_target(host_path)
        try:
            target.rmdir()
        except (FileNotFoundError, OSError):
            return

    def _mounted_data_path(self, instance: Instance) -> Path:
        source = self._host_data_path(instance.container)
        candidates: list[tuple[int, Path]] = []
        for host_root, container_root in self._managed_mounts():
            try:
                relative = source.relative_to(host_root)
            except ValueError:
                continue
            candidate = (container_root / Path(*relative.parts)).resolve()
            try:
                candidate.relative_to(self.managed_root)
            except ValueError:
                continue
            candidates.append((len(host_root.parts), candidate))
        if not candidates:
            raise DataAccessError(
                f"el volumen /data de {instance.container} queda fuera de la "
                "raíz montada en /instances")
        candidates.sort(key=lambda item: item[0], reverse=True)
        resolved = candidates[0][1]
        if not resolved.is_dir():
            raise DataAccessError(
                f"no existe la carpeta montada de {instance.id}: {resolved}")
        return resolved

    def _effective_instance(self, instance: Instance) -> Instance:
        mounted = self._mounted_data_path(instance)
        configured = instance.data_dir.resolve()
        if instance.data_backend != "docker" and configured != mounted:
            raise DataAccessError(
                f"data_dir de {instance.id} no corresponde al volumen /data "
                f"de {instance.container}")
        return replace(instance, data_dir=mounted, data_backend="direct")

    def create_snapshot(
        self,
        instance: Instance,
        source_node: str,
        token: str,
        output: Path,
        max_bytes: int,
        parent_fingerprint: str | None = None,
        ancestor_fingerprints: list[str] | None = None,
    ) -> dict:
        effective = self._effective_instance(instance)
        return snapshot.create_snapshot(
            effective,
            source_node,
            token,
            output,
            max_bytes,
            parent_fingerprint,
            ancestor_fingerprints,
        )

    def apply_snapshot(
        self,
        instance: Instance,
        payload: bytes,
        token: str,
        max_bytes: int,
    ) -> dict:
        effective = self._effective_instance(instance)
        return snapshot.apply_snapshot(effective, payload, token, max_bytes)

    def backend(self, instance: Instance) -> str:
        """Valida el bind declarado y confirma acceso directo desde Guardian."""
        self._effective_instance(instance)
        return "direct"

    def inspect_data(self, instance: Instance, token: str, max_bytes: int) -> dict:
        """Sólo informa si el destino está vacío; nunca devuelve contenido."""
        del token, max_bytes
        effective = self._effective_instance(instance)
        try:
            entries = sorted(item.name for item in effective.data_dir.iterdir())
        except OSError as exc:
            raise DataAccessError(
                f"no se puede inspeccionar {effective.data_dir}") from exc
        return {
            "empty": not entries,
            "entries": entries[:20],
            "truncated": len(entries) > 20,
            "backend": "direct",
        }

"""Snapshots consistentes y restauración con validación de rutas."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from config import Instance


class SnapshotError(RuntimeError):
    """El estado no se puede empaquetar, validar o restaurar."""


MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES = 4096
MAX_ARCHIVE_TEXT_METADATA_BYTES = 4096
MAX_ARCHIVE_PAX_HEADERS = 32
MAX_ARCHIVE_PAX_BYTES = 64 * 1024
MAX_ARCHIVE_METADATA_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 64
SHA256 = re.compile(r"[0-9a-f]{64}")


class _BoundedTarInfo(tarfile.TarInfo):
    """Impide que metadatos TAR ocultos se descompriman sin límite."""

    def _proc_member(self, archive):
        header_count = getattr(archive, "_vg_header_count", 0) + 1
        archive._vg_header_count = header_count
        if header_count > MAX_ARCHIVE_MEMBERS:
            raise SnapshotError("el paquete contiene demasiados miembros TAR")

        hidden = self.type in {
            tarfile.XGLTYPE,
            tarfile.SOLARIS_XHDTYPE,
            tarfile.XHDTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.GNUTYPE_SPARSE,
        }
        if hidden:
            hidden_depth = getattr(archive, "_vg_hidden_depth", 0) + 1
            archive._vg_hidden_depth = hidden_depth
            if hidden_depth > MAX_ARCHIVE_DEPTH:
                raise SnapshotError(
                    "los metadatos TAR ocultos superan la profundidad permitida")
            hidden_bytes = getattr(archive, "_vg_hidden_bytes", 0) + max(
                0, self.size)
            archive._vg_hidden_bytes = hidden_bytes
            if hidden_bytes > MAX_ARCHIVE_METADATA_BYTES:
                raise SnapshotError(
                    "los metadatos TAR ocultos superan el límite agregado")
        if self.type in {tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE}:
            raise SnapshotError("los metadatos TAR globales no están permitidos")
        if self.type == tarfile.XHDTYPE and self.size > MAX_ARCHIVE_PAX_BYTES:
            raise SnapshotError("metadatos TAR extendidos demasiado grandes")
        if self.type == tarfile.GNUTYPE_LONGNAME and self.size > MAX_ARCHIVE_PATH_BYTES + 1:
            raise SnapshotError("ruta TAR extendida demasiado grande")
        if self.type in {tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE}:
            raise SnapshotError("tipo de metadato TAR no aceptado")
        try:
            return super()._proc_member(archive)
        finally:
            if hidden:
                archive._vg_hidden_depth -= 1


def _fernet(token: str) -> Fernet:
    if len(token) < 32:
        raise SnapshotError("el token de replicación debe tener al menos 32 caracteres")
    key = base64.urlsafe_b64encode(hashlib.sha256(("vault-guardian:" + token).encode()).digest())
    return Fernet(key)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unpacked_limit(max_bytes: int) -> int:
    if max_bytes < 1:
        raise SnapshotError("el límite del paquete no es válido")
    return min(MAX_UNPACKED_BYTES, max_bytes * 4)


def _inside(root: Path, target: Path) -> None:
    try:
        if os.path.commonpath((str(root), str(target.resolve(strict=False)))) != str(root):
            raise SnapshotError(f"ruta fuera del volumen: {target}")
    except ValueError as exc:
        raise SnapshotError(f"ruta fuera del volumen: {target}") from exc


def _source_flags(*, directory: bool = False) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise SnapshotError("la plataforma no permite abrir fuentes sin seguir enlaces")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise SnapshotError("la plataforma no permite fijar directorios de origen")
        flags |= os.O_DIRECTORY
    return flags


def _open_source_directory(path: Path | str, *, dir_fd: int | None = None) -> int:
    descriptor = os.open(path, _source_flags(directory=True), dir_fd=dir_fd)
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise SnapshotError(f"tipo de directorio no aceptado: {path}")
    return descriptor


def _open_source_file(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        raise SnapshotError(f"no se aceptan enlaces simbólicos: {name}")
    if not stat.S_ISREG(before.st_mode):
        raise SnapshotError(f"tipo de archivo no aceptado: {name}")
    descriptor = os.open(name, _source_flags(), dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    if (
        not stat.S_ISREG(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
    ):
        os.close(descriptor)
        raise SnapshotError(f"el archivo cambió durante la captura: {name}")
    return descriptor, opened


def _capture_source_file(
    parent_fd: int,
    name: str,
    destination: Path,
    max_bytes: int,
) -> tuple[int, str]:
    descriptor, before = _open_source_file(parent_fd, name)
    output = -1
    created = False
    complete = False
    try:
        if before.st_size < 0 or before.st_size > max_bytes:
            raise SnapshotError(
                f"los datos sin comprimir superan el límite de seguridad: {name}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        output_flags |= getattr(os, "O_NOFOLLOW", 0)
        output = os.open(destination, output_flags, 0o600)
        created = True
        digest = hashlib.sha256()
        written = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, max_bytes - written + 1))
            if not block:
                break
            written += len(block)
            if written > max_bytes:
                raise SnapshotError(
                    f"los datos sin comprimir superan el límite de seguridad: {name}")
            digest.update(block)
            view = memoryview(block)
            while view:
                consumed = os.write(output, view)
                if consumed <= 0:
                    raise OSError("escritura incompleta durante la captura")
                view = view[consumed:]
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
        )
        if (
            written != before.st_size
            or any(getattr(before, field) != getattr(after, field)
                   for field in stable_fields)
        ):
            raise SnapshotError(f"el archivo cambió durante la captura: {name}")
        os.fchmod(output, 0o600)
        complete = True
        return written, digest.hexdigest()
    finally:
        os.close(descriptor)
        if output >= 0:
            os.close(output)
        if created and not complete:
            destination.unlink(missing_ok=True)


def _backup_sqlite(root_fd: int, destination: Path, max_bytes: int) -> None:
    descriptor, before = _open_source_file(root_fd, "db.sqlite3")
    if before.st_size < 0 or before.st_size > max_bytes:
        os.close(descriptor)
        raise SnapshotError(
            "los datos sin comprimir superan el límite de seguridad: db.sqlite3")
    try:
        origin = None
        target = None
        origin = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro", uri=True)
        target = sqlite3.connect(destination)
        with target:
            origin.backup(target, pages=1000, sleep=0.05)
        result = target.execute("PRAGMA integrity_check").fetchone()
        after = os.fstat(descriptor)
    except sqlite3.Error as exc:
        raise SnapshotError(f"backup SQLite fallido: {type(exc).__name__}") from exc
    finally:
        if target is not None:
            target.close()
        if origin is not None:
            origin.close()
        os.close(descriptor)
    if not result or result[0] != "ok":
        raise SnapshotError("integrity_check de SQLite no devuelve ok")
    if (
        (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or after.st_size < 0
        or after.st_size > max_bytes
        or destination.stat().st_size > max_bytes
    ):
        raise SnapshotError("la base SQLite cambió fuera de los límites durante la captura")


def _validate_sqlite(path: Path) -> None:
    connection = None
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        result = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        raise SnapshotError(
            f"base SQLite restaurada no válida: {type(exc).__name__}") from exc
    finally:
        if connection is not None:
            connection.close()
    if not result or result[0] != "ok":
        raise SnapshotError("integrity_check de SQLite no devuelve ok")


def _write_atomic_bytes(target: Path, payload: bytes) -> None:
    """Publica un fichero completo desde el mismo filesystem sin seguir el destino."""
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".new", dir=target.parent
    )
    temporary = Path(temporary_name)
    published = False
    try:
        written = 0
        view = memoryview(payload)
        while view:
            consumed = os.write(descriptor, view)
            if consumed <= 0:
                raise OSError("escritura incompleta del paquete")
            written += consumed
            view = view[consumed:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        created = os.fstat(descriptor)
        current = temporary.lstat()
        if (
            written != len(payload)
            or not stat.S_ISREG(current.st_mode)
            or (created.st_dev, created.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise SnapshotError("el fichero temporal del paquete cambió")
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        final = target.lstat()
        if (
            not stat.S_ISREG(final.st_mode)
            or (final.st_dev, final.st_ino) != (created.st_dev, created.st_ino)
        ):
            raise SnapshotError("el paquete publicado cambió")
        published = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            temporary.unlink(missing_ok=True)


def create_snapshot(instance: Instance, source_node: str, token: str,
                    output: Path, max_bytes: int = 256 * 1024 * 1024,
                    parent_fingerprint: str | None = None,
                    ancestor_fingerprints: list[str] | None = None) -> dict:
    try:
        return _create_snapshot(
            instance, source_node, token, output, max_bytes,
            parent_fingerprint, ancestor_fingerprints)
    except OSError as exc:
        raise SnapshotError(
            f"no se pudo crear el snapshot: {type(exc).__name__}") from exc


def _create_snapshot(instance: Instance, source_node: str, token: str,
                     output: Path, max_bytes: int,
                     parent_fingerprint: str | None,
                     ancestor_fingerprints: list[str] | None) -> dict:
    """Crea un paquete cifrado; nunca modifica el volumen de origen."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vg-snapshot-") as directory:
        work = Path(directory)
        captured = work / "captured"
        captured_data = captured / "data"
        captured_data.mkdir(parents=True)
        captured.chmod(0o700)
        captured_data.chmod(0o700)
        managed = ["config.json", "attachments", "sends"]
        unpacked_limit = _unpacked_limit(max_bytes)
        unpacked_bytes = 0
        archive_members = 2  # manifest.json y el directorio data
        manifest_entries: list[dict] = []

        def reserve_member(archive_name: str) -> None:
            nonlocal archive_members
            if _safe_member(archive_name) != archive_name:
                raise SnapshotError(f"ruta no válida durante la captura: {archive_name}")
            if len(archive_name.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES:
                raise SnapshotError(f"ruta demasiado larga durante la captura: {archive_name}")
            archive_members += 1
            if archive_members > MAX_ARCHIVE_MEMBERS:
                raise SnapshotError("el snapshot contiene demasiados miembros")

        def add_private_file(source: Path, archive_name: str) -> None:
            nonlocal unpacked_bytes
            reserve_member(archive_name)
            metadata = source.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise SnapshotError(f"tipo de archivo no aceptado: {archive_name}")
            size = metadata.st_size
            unpacked_bytes += size
            if unpacked_bytes > unpacked_limit:
                raise SnapshotError(
                    "los datos sin comprimir superan el límite de seguridad")
            manifest_entries.append({
                "path": archive_name,
                "size": size,
                "sha256": _hash_file(source),
            })

        def capture_file(parent_fd: int, name: str, archive_name: str) -> None:
            nonlocal unpacked_bytes
            reserve_member(archive_name)
            destination = captured / archive_name
            size, digest = _capture_source_file(
                parent_fd, name, destination, unpacked_limit - unpacked_bytes
            )
            unpacked_bytes += size
            manifest_entries.append({
                "path": archive_name,
                "size": size,
                "sha256": digest,
            })

        def capture_tree(
            parent_fd: int, name: str, archive_name: str, depth: int = 1
        ) -> None:
            if depth > MAX_ARCHIVE_DEPTH:
                raise SnapshotError("el snapshot supera la profundidad permitida")
            reserve_member(archive_name)
            destination = captured / archive_name
            destination.mkdir()
            destination.chmod(0o700)
            directory_fd = _open_source_directory(name, dir_fd=parent_fd)
            try:
                with os.scandir(directory_fd) as iterator:
                    names = []
                    for entry in iterator:
                        names.append(entry.name)
                        if len(names) > MAX_ARCHIVE_MEMBERS:
                            raise SnapshotError(
                                "el snapshot contiene demasiados miembros")
                for child_name in sorted(names):
                    child_archive = f"{archive_name}/{child_name}"
                    metadata = os.stat(
                        child_name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if stat.S_ISLNK(metadata.st_mode):
                        raise SnapshotError(
                            f"no se aceptan enlaces simbólicos: {child_archive}")
                    if stat.S_ISREG(metadata.st_mode):
                        capture_file(directory_fd, child_name, child_archive)
                    elif stat.S_ISDIR(metadata.st_mode):
                        capture_tree(
                            directory_fd, child_name, child_archive, depth + 1
                        )
                    else:
                        raise SnapshotError(
                            f"tipo de archivo no aceptado: {child_archive}")
            finally:
                os.close(directory_fd)

        root_fd = _open_source_directory(instance.data_dir)
        try:
            database = captured_data / "db.sqlite3"
            _backup_sqlite(root_fd, database, unpacked_limit)
            database.chmod(0o600)
            add_private_file(database, "data/db.sqlite3")

            with os.scandir(root_fd) as iterator:
                root_names = []
                for entry in iterator:
                    if (
                        entry.name in {"config.json", "attachments", "sends"}
                        or entry.name.startswith("rsa_key")
                    ):
                        root_names.append(entry.name)
                        if len(root_names) > MAX_ARCHIVE_MEMBERS:
                            raise SnapshotError(
                                "el snapshot contiene demasiados miembros")
            available = set(root_names)
            for name in sorted(
                item for item in available
                if item == "config.json" or item.startswith("rsa_key")
            ):
                capture_file(root_fd, name, f"data/{name}")
            for name in ("attachments", "sends"):
                if name == "sends" and not instance.include_sends:
                    continue
                if name in available:
                    capture_tree(root_fd, name, f"data/{name}")
        finally:
            os.close(root_fd)

        manifest = {
            "format": 1,
            "instance": instance.id,
            "source_node": source_node,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "managed": managed,
            "include_sends": instance.include_sends,
            "entries": manifest_entries,
            "parent_fingerprint": parent_fingerprint,
            "ancestor_fingerprints": list(ancestor_fingerprints or [])[:64],
        }
        manifest_file = work / "manifest.json"
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise SnapshotError("manifest.json supera el límite de seguridad")
        manifest_file.write_bytes(manifest_bytes)
        raw_file = work / "package.tar.gz"
        with tarfile.open(raw_file, "w:gz") as archive:
            archive.add(manifest_file, arcname="manifest.json")
            archive.add(captured_data, arcname="data", recursive=True)
        if raw_file.stat().st_size > max_bytes:
            raise SnapshotError("el tar.gz supera el límite del paquete")
        raw = raw_file.read_bytes()
        validated, _ = _validate_archive(raw, max_bytes)
        if validated != manifest:
            raise SnapshotError("manifest.json cambió durante la creación")
        encrypted = _fernet(token).encrypt(raw)
        if len(encrypted) > max_bytes:
            raise SnapshotError(f"paquete de {len(encrypted)} bytes supera el límite")
        _write_atomic_bytes(output, encrypted)
        return {"bytes": len(encrypted), "sha256": hashlib.sha256(encrypted).hexdigest(),
                "manifest": manifest}


def _decrypt(payload: bytes, token: str,
             max_age_seconds: int | None = 900) -> bytes:
    try:
        cipher = _fernet(token)
        if max_age_seconds is None:
            return cipher.decrypt(payload)
        return cipher.decrypt(payload, ttl=max_age_seconds)
    except (InvalidToken, SnapshotError) as exc:
        raise SnapshotError("paquete no válido, caducado o no descifrable") from exc


def read_manifest(payload: bytes, token: str, max_bytes: int) -> tuple[dict, bytes]:
    if len(payload) > max_bytes:
        raise SnapshotError("paquete recibido demasiado grande")
    raw = _decrypt(payload, token)
    manifest, _ = _validate_archive(raw, max_bytes)
    return manifest, raw


def refresh_backup(payload: bytes, token: str,
                   max_bytes: int) -> tuple[dict, bytes]:
    """Renueva un backup local autenticado sin relajar el TTL de recepción."""
    if len(payload) > max_bytes:
        raise SnapshotError("paquete recibido demasiado grande")
    raw = _decrypt(payload, token, max_age_seconds=None)
    manifest, _ = _validate_archive(raw, max_bytes)
    refreshed = _fernet(token).encrypt(raw)
    if len(refreshed) > max_bytes:
        raise SnapshotError(
            f"paquete de {len(refreshed)} bytes supera el límite")
    return manifest, refreshed


def _validate_manifest(manifest: object, unpacked_limit: int) -> dict[str, dict]:
    if not isinstance(manifest, dict) or manifest.get("format") != 1:
        raise SnapshotError("manifest.json no cumple el formato 1")
    required_fields = {
        "format", "instance", "source_node", "created_at", "managed",
        "include_sends", "entries", "parent_fingerprint",
        "ancestor_fingerprints",
    }
    if set(manifest) != required_fields:
        raise SnapshotError("manifest.json contiene campos desconocidos o incompletos")
    for field in ("instance", "source_node"):
        value = manifest.get(field)
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 128
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value)
        ):
            raise SnapshotError(f"{field} no es válido en manifest.json")
    created_at = manifest.get("created_at")
    if (
        not isinstance(created_at, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created_at)
    ):
        raise SnapshotError("created_at no es válido en manifest.json")
    try:
        time.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SnapshotError("created_at no es válido en manifest.json") from exc
    if manifest.get("managed") != ["config.json", "attachments", "sends"]:
        raise SnapshotError("managed no es válido en manifest.json")
    include_sends = manifest.get("include_sends")
    if not isinstance(include_sends, bool):
        raise SnapshotError("include_sends no es válido en manifest.json")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise SnapshotError("manifest.json no contiene entries")
    if len(entries) >= MAX_ARCHIVE_MEMBERS:
        raise SnapshotError("manifest.json contiene demasiadas entradas")
    expected: dict[str, dict] = {}
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise SnapshotError("manifest.json contiene una entrada no válida")
        path = entry.get("path")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(path, str)
            or _safe_member(path) != path
            or not _allowed_entry_path(path, include_sends)
        ):
            raise SnapshotError("manifest.json contiene una ruta no válida")
        if path in expected:
            raise SnapshotError("manifest.json contiene rutas duplicadas")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise SnapshotError("manifest.json contiene un tamaño no válido")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise SnapshotError("manifest.json contiene un hash no válido")
        total += size
        if total > unpacked_limit:
            raise SnapshotError(
                "los datos sin comprimir superan el límite de seguridad")
        expected[path] = entry
    if "data/db.sqlite3" not in expected:
        raise SnapshotError("el paquete no contiene data/db.sqlite3")
    parent = manifest.get("parent_fingerprint")
    if parent is not None and (
        not isinstance(parent, str) or not SHA256.fullmatch(parent)
    ):
        raise SnapshotError("parent_fingerprint no es válido")
    ancestors = manifest.get("ancestor_fingerprints", [])
    if (
        not isinstance(ancestors, list)
        or len(ancestors) > 64
        or any(not isinstance(item, str) or not SHA256.fullmatch(item)
               for item in ancestors)
    ):
        raise SnapshotError("ancestor_fingerprints no es válido")
    return expected


def _safe_member(name: str) -> str:
    normalized = name.replace("\\", "/")
    components = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or any(character in normalized for character in ("\x00", "\r", "\n"))
        or ".." in components
        or "." in components
        or "" in components
    ):
        raise SnapshotError(f"ruta peligrosa en paquete: {name!r}")
    if normalized not in {"manifest.json", "data"} and not normalized.startswith("data/"):
        raise SnapshotError(f"ruta fuera de data en paquete: {name!r}")
    return normalized


def _allowed_entry_path(path: str, include_sends: bool) -> bool:
    if path in {"data/db.sqlite3", "data/config.json"}:
        return True
    if re.fullmatch(r"data/rsa_key[^/]*", path):
        return True
    if path.startswith("data/attachments/"):
        return True
    return include_sends and path.startswith("data/sends/")


def _validate_archive_member(
    member: tarfile.TarInfo, name: str
) -> tuple[str, int]:
    """Acepta sólo metadatos TAR acotados que la restauración entiende."""
    try:
        path_bytes = len(name.encode("utf-8"))
        text_bytes = sum(
            len(value.encode("utf-8"))
            for value in (member.linkname, member.uname, member.gname)
        )
        pax_bytes = sum(
            len(key.encode("utf-8")) + len(value.encode("utf-8"))
            for key, value in member.pax_headers.items()
        )
    except (AttributeError, UnicodeEncodeError) as exc:
        raise SnapshotError(f"metadatos no válidos: {name}") from exc
    if (
        path_bytes > MAX_ARCHIVE_PATH_BYTES
        or text_bytes > MAX_ARCHIVE_TEXT_METADATA_BYTES
        or len(member.pax_headers) > MAX_ARCHIVE_PAX_HEADERS
        or pax_bytes > MAX_ARCHIVE_PAX_BYTES
    ):
        raise SnapshotError(f"metadatos demasiado grandes: {name}")
    if member.linkname:
        raise SnapshotError(f"enlace no aceptado: {name}")
    if (
        isinstance(member.uid, bool)
        or not isinstance(member.uid, int)
        or not 0 <= member.uid <= 0xFFFFFFFF
        or isinstance(member.gid, bool)
        or not isinstance(member.gid, int)
        or not 0 <= member.gid <= 0xFFFFFFFF
        or isinstance(member.mode, bool)
        or not isinstance(member.mode, int)
        or not 0 <= member.mode <= 0o7777
        or isinstance(member.mtime, bool)
        or not isinstance(member.mtime, (int, float))
        or not math.isfinite(member.mtime)
        or not -(2 ** 63) <= member.mtime <= 2 ** 63 - 1
        or isinstance(member.devmajor, bool)
        or not isinstance(member.devmajor, int)
        or not 0 <= member.devmajor <= 0xFFFFFFFF
        or isinstance(member.devminor, bool)
        or not isinstance(member.devminor, int)
        or not 0 <= member.devminor <= 0xFFFFFFFF
    ):
        raise SnapshotError(f"metadatos numéricos no válidos: {name}")
    if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
        if member.size < 0:
            raise SnapshotError(f"tamaño no válido: {name}")
        kind = "file"
    elif member.type == tarfile.DIRTYPE:
        if member.size != 0:
            raise SnapshotError(f"directorio con tamaño no válido: {name}")
        kind = "directory"
    else:
        raise SnapshotError(f"tipo de miembro no aceptado: {name}")

    for root in ("data/attachments", "data/sends"):
        if name == root:
            tree_depth = 1
        elif name.startswith(root + "/"):
            tail_depth = len(name[len(root) + 1:].split("/"))
            tree_depth = tail_depth + (1 if kind == "directory" else 0)
        else:
            continue
        if tree_depth > MAX_ARCHIVE_DEPTH:
            raise SnapshotError(
                f"la ruta TAR supera la profundidad permitida: {name}")
        break
    return kind, path_bytes + text_bytes + pax_bytes


def _validate_archive(raw: bytes, max_bytes: int) -> tuple[dict, dict[str, dict]]:
    unpacked_limit = _unpacked_limit(max_bytes)
    names: set[str] = set()
    directories: set[str] = set()
    files: dict[str, int] = {}
    hashes: dict[str, str] = {}
    total = 0
    metadata_total = 0
    count = 0
    manifest: object | None = None
    try:
        with tarfile.open(
            fileobj=io.BytesIO(raw), mode="r|gz", tarinfo=_BoundedTarInfo
        ) as archive:
            for member in archive:
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    raise SnapshotError("el paquete contiene demasiados miembros")
                name = _safe_member(member.name)
                if name in names:
                    raise SnapshotError("el paquete contiene rutas duplicadas")
                names.add(name)
                kind, metadata_bytes = _validate_archive_member(member, name)
                metadata_total += metadata_bytes
                if metadata_total > MAX_ARCHIVE_METADATA_BYTES:
                    raise SnapshotError(
                        "los metadatos TAR agregados superan el límite")
                if kind == "directory":
                    directories.add(name)
                if kind == "file":
                    total += member.size
                    if total > unpacked_limit + MAX_MANIFEST_BYTES:
                        raise SnapshotError(
                            "los datos sin comprimir superan el límite de seguridad")
                    files[name] = member.size
                if name == "manifest.json":
                    if not member.isfile() or member.size > MAX_MANIFEST_BYTES:
                        raise SnapshotError(
                            "manifest.json supera el límite de seguridad")
                if kind == "file":
                    source = archive.extractfile(member)
                    if source is None:
                        raise SnapshotError(f"miembro sin contenido: {name}")
                    digest = hashlib.sha256()
                    written = 0
                    encoded = bytearray() if name == "manifest.json" else None
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        written += len(block)
                        if written > member.size:
                            raise SnapshotError(f"miembro demasiado grande: {name}")
                        digest.update(block)
                        if encoded is not None:
                            encoded.extend(block)
                    if written != member.size:
                        raise SnapshotError(f"miembro incompleto: {name}")
                    hashes[name] = digest.hexdigest()
                    if encoded is not None:
                        manifest = json.loads(bytes(encoded).decode("utf-8"))
    except (tarfile.TarError, OSError, EOFError, UnicodeDecodeError,
            json.JSONDecodeError) as exc:
        raise SnapshotError("el paquete no contiene un tar.gz válido") from exc
    if manifest is None:
        raise SnapshotError("falta o es inválido manifest.json")
    expected = _validate_manifest(manifest, unpacked_limit)
    allowed_directories = {"data"}
    for name in expected:
        parts = name.split("/")[:-1]
        allowed_directories.update(
            "/".join(parts[:index]) for index in range(1, len(parts) + 1))
    managed_directory_roots = {"data/attachments"}
    if manifest["include_sends"]:
        managed_directory_roots.add("data/sends")
    if any(
        directory not in allowed_directories
        and not any(
            directory == root or directory.startswith(root + "/")
            for root in managed_directory_roots
        )
        for directory in directories
    ):
        raise SnapshotError("el paquete contiene directorios no declarados")
    archive_files = {name: size for name, size in files.items()
                     if name != "manifest.json"}
    if set(archive_files) != set(expected):
        raise SnapshotError("el contenido no coincide con manifest.json")
    if any(archive_files[name] != expected[name]["size"] for name in expected):
        raise SnapshotError("los tamaños no coinciden con manifest.json")
    for name, entry in expected.items():
        if hashes.get(name) != entry["sha256"]:
            raise SnapshotError(f"hash incorrecto en {name}")
    return manifest, expected


def _extract(raw: bytes, stage: Path, manifest: dict, max_bytes: int) -> None:
    expected = _validate_manifest(manifest, _unpacked_limit(max_bytes))
    allowed_directories = {"data"}
    for name in expected:
        parts = name.split("/")[:-1]
        allowed_directories.update(
            "/".join(parts[:index]) for index in range(1, len(parts) + 1))
    managed_directory_roots = {"data/attachments"}
    if manifest["include_sends"]:
        managed_directory_roots.add("data/sends")
    total = 0
    metadata_total = 0
    count = 0
    try:
        with tarfile.open(
            fileobj=io.BytesIO(raw), mode="r|gz", tarinfo=_BoundedTarInfo
        ) as archive:
            for member in archive:
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    raise SnapshotError("el paquete contiene demasiados miembros")
                name = _safe_member(member.name)
                kind, metadata_bytes = _validate_archive_member(member, name)
                metadata_total += metadata_bytes
                if metadata_total > MAX_ARCHIVE_METADATA_BYTES:
                    raise SnapshotError(
                        "los metadatos TAR agregados superan el límite")
                if name == "manifest.json":
                    if kind != "file":
                        raise SnapshotError(
                            "manifest.json no es un fichero regular")
                    continue
                destination = stage / name
                _inside(stage, destination)
                if kind == "directory":
                    if (
                        name not in allowed_directories
                        and not any(
                            name == root or name.startswith(root + "/")
                            for root in managed_directory_roots
                        )
                    ):
                        raise SnapshotError(
                            f"directorio no declarado: {name}")
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if kind != "file" or name not in expected:
                    raise SnapshotError(f"tipo de miembro no aceptado: {name}")
                total += member.size
                if total > _unpacked_limit(max_bytes):
                    raise SnapshotError(
                        "los datos sin comprimir superan el límite de seguridad")
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise SnapshotError(f"miembro sin contenido: {name}")
                written = 0
                with destination.open("xb") as target_file:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        written += len(block)
                        if written > member.size:
                            raise SnapshotError(f"miembro demasiado grande: {name}")
                        target_file.write(block)
                if written != member.size:
                    raise SnapshotError(f"miembro incompleto: {name}")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise SnapshotError("no se pudo extraer el paquete") from exc

    actual: set[str] = set()
    data = stage / "data"
    for path in data.rglob("*"):
        if path.is_symlink():
            raise SnapshotError("la extracción contiene un enlace simbólico")
        if path.is_file():
            path.chmod(0o600)
            actual.add(f"data/{path.relative_to(data).as_posix()}")
        elif path.is_dir():
            path.chmod(0o700)
    data.chmod(0o700)
    if actual != set(expected):
        raise SnapshotError("la extracción no coincide con manifest.json")
    for name, entry in expected.items():
        path = stage / name
        if path.stat().st_size != entry["size"] or _hash_file(path) != entry["sha256"]:
            raise SnapshotError(f"hash incorrecto en {name}")


def apply_snapshot(instance: Instance, payload: bytes, token: str, max_bytes: int) -> dict:
    try:
        return _apply_snapshot(instance, payload, token, max_bytes)
    except OSError as exc:
        raise SnapshotError(
            f"no se pudo aplicar el snapshot: {type(exc).__name__}") from exc


def _apply_snapshot(instance: Instance, payload: bytes,
                    token: str, max_bytes: int) -> dict:
    manifest, raw = read_manifest(payload, token, max_bytes)
    if manifest["instance"] != instance.id:
        raise SnapshotError("la instancia del paquete no coincide con el destino")
    if manifest["include_sends"] is not instance.include_sends:
        raise SnapshotError(
            "include_sends del paquete no coincide con la instancia de destino")
    with tempfile.TemporaryDirectory(prefix="vg-restore-") as directory:
        stage = Path(directory)
        _extract(raw, stage, manifest, max_bytes)
        db = stage / "data/db.sqlite3"
        _validate_sqlite(db)
        destination = instance.data_dir
        destination.mkdir(parents=True, exist_ok=True)
        _replace_file(db, destination / "db.sqlite3")
        _replace_file(stage / "data/config.json", destination / "config.json", remove_if_missing=True)
        for source in destination.glob("rsa_key*"):
            source.unlink(missing_ok=True)
        for source in (stage / "data").glob("rsa_key*"):
            _replace_file(source, destination / source.name)
        for directory_name in ("attachments", "sends"):
            if directory_name == "sends" and not instance.include_sends:
                continue
            target = destination / directory_name
            _remove_managed_path(target)
            source = stage / "data" / directory_name
            if source.exists():
                shutil.copytree(source, target)
            _require_missing_or_directory(target, source.exists())
        (destination / "db.sqlite3-wal").unlink(missing_ok=True)
        (destination / "db.sqlite3-shm").unlink(missing_ok=True)
    return {"ok": True, "instance": instance.id, "source_node": manifest["source_node"],
            "created_at": manifest["created_at"]}


def _remove_managed_path(target: Path) -> None:
    """Elimina exactamente una ruta gestionada sin seguir enlaces simbólicos."""
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
        shutil.rmtree(target)
    else:
        target.unlink()
    try:
        target.lstat()
    except FileNotFoundError:
        return
    raise SnapshotError(f"no se pudo limpiar la ruta gestionada: {target.name}")


def _require_missing_or_directory(target: Path, expected: bool) -> None:
    """Comprueba la poscondición exacta tras sustituir un árbol gestionado."""
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        if expected:
            raise SnapshotError(
                f"falta la ruta gestionada restaurada: {target.name}")
        return
    if not expected or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotError(
            f"la ruta gestionada no coincide con el snapshot: {target.name}")


def _replace_file(source: Path, target: Path, remove_if_missing: bool = False) -> None:
    if not source.exists():
        if remove_if_missing:
            target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.vault-guardian-new")
    temporary.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    created = None
    try:
        with source.open("rb") as source_file, os.fdopen(descriptor, "wb") as target_file:
            descriptor = -1
            shutil.copyfileobj(source_file, target_file, 1024 * 1024)
            target_file.flush()
            created = os.fstat(target_file.fileno())
            os.fchmod(target_file.fileno(), stat.S_IMODE(source.stat().st_mode))
        current = temporary.lstat()
        if (
            created is None
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino)
        ):
            raise SnapshotError("el fichero temporal de restauración cambió")
        os.replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)

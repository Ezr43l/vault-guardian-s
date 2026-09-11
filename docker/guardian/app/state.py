"""Estado operativo persistente, sin secretos ni contenido de las bóvedas."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path


_TRANSACTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
DEFAULT_HISTORY_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_HISTORY_MAX_ENTRIES = 5_000
MAX_HISTORY_RECORD_BYTES = 1024 * 1024
_HISTORY_CHUNK_BYTES = 64 * 1024


class StateError(RuntimeError):
    """El estado persistente no se puede manipular con seguridad."""


class StateStore:
    def __init__(
        self,
        state_dir: Path,
        node: str,
        history_max_bytes: int = DEFAULT_HISTORY_MAX_BYTES,
        history_max_entries: int = DEFAULT_HISTORY_MAX_ENTRIES,
    ):
        if not 1024 <= int(history_max_bytes) <= 256 * 1024 * 1024:
            raise ValueError("history_max_bytes queda fuera del límite permitido")
        if not 2 <= int(history_max_entries) <= 100_000:
            raise ValueError("history_max_entries queda fuera del límite permitido")
        self.state_dir = state_dir
        self.node = node
        self.history_max_bytes = int(history_max_bytes)
        self.history_max_entries = int(history_max_entries)
        self._history_identity: tuple[int, int, int, int] | None = None
        self._history_count: int | None = None
        self._lock = threading.RLock()

    @staticmethod
    def now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _result_path(self, instance_id: str) -> Path:
        return self.state_dir / "operations" / f"{instance_id}.json"

    def _content_path(self, instance_id: str) -> Path:
        return self.state_dir / "replication" / f"{instance_id}.json"

    def _provisioning_path(self, transaction: str) -> Path:
        if not _TRANSACTION.fullmatch(transaction or ""):
            raise ValueError("identificador de transacción no válido")
        return self.state_dir / "provisioning" / f"{transaction}.json"

    @property
    def history_path(self) -> Path:
        return self.state_dir / "history.jsonl"

    @staticmethod
    def _history_identity_for(metadata: os.stat_result) -> tuple[int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )

    @staticmethod
    def _check_history_descriptor(descriptor: int) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StateError("history.jsonl debe ser un fichero regular sin enlaces")
        return metadata

    def _history_parent(self) -> Path:
        parent = self.history_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise StateError("no se puede abrir el directorio de historial") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise StateError("el directorio de historial no es seguro")
        return parent

    def _open_history(self, *, create: bool) -> int:
        if not hasattr(os, "O_NOFOLLOW"):
            raise StateError("la plataforma no permite abrir el historial sin seguir enlaces")
        try:
            existing = self.history_path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise StateError("no se puede inspeccionar history.jsonl") from exc
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
        ):
            raise StateError("history.jsonl debe ser un fichero regular sin enlaces")
        if existing is None and not create:
            return -1
        flags = (os.O_RDWR | os.O_APPEND) if create else os.O_RDONLY
        flags |= os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        if create:
            flags |= os.O_CREAT
        try:
            descriptor = os.open(self.history_path, flags, 0o600)
        except FileNotFoundError:
            if not create:
                return -1
            raise
        except OSError as exc:
            raise StateError("no se puede abrir history.jsonl de forma segura") from exc
        try:
            self._check_history_descriptor(descriptor)
            if create:
                os.fchmod(descriptor, 0o600)
        except (OSError, StateError):
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("escritura incompleta del historial")
            view = view[written:]

    @staticmethod
    def _count_history_lines(descriptor: int, size: int) -> int:
        position = 0
        count = 0
        last = b""
        while position < size:
            os.lseek(descriptor, position, os.SEEK_SET)
            block = os.read(descriptor, min(_HISTORY_CHUNK_BYTES, size - position))
            if not block:
                break
            position += len(block)
            count += block.count(b"\n")
            last = block[-1:]
        if size and last != b"\n":
            count += 1
        return count

    @staticmethod
    def _history_ends_with_newline(descriptor: int, size: int) -> bool:
        if size == 0:
            return True
        os.lseek(descriptor, size - 1, os.SEEK_SET)
        return os.read(descriptor, 1) == b"\n"

    @staticmethod
    def _reverse_history_lines(
        descriptor: int,
        size: int,
        max_scan_bytes: int,
    ):
        """Itera líneas completas desde el final con memoria e I/O acotados."""
        minimum_position = max(0, size - max_scan_bytes)
        position = size
        suffix = b""
        oversized = False
        while position > minimum_position:
            amount = min(_HISTORY_CHUNK_BYTES, position - minimum_position)
            position -= amount
            os.lseek(descriptor, position, os.SEEK_SET)
            block = os.read(descriptor, amount)
            if len(block) != amount:
                raise StateError("history.jsonl cambió durante la lectura")
            parts = block.split(b"\n")
            right = parts.pop()
            if oversized or len(right) + len(suffix) > MAX_HISTORY_RECORD_BYTES:
                candidate = None
            else:
                candidate = right + suffix
            if parts:
                if candidate:
                    yield candidate
                for line in reversed(parts[1:]):
                    if line and len(line) <= MAX_HISTORY_RECORD_BYTES:
                        yield line
                suffix = parts[0] if len(parts[0]) <= MAX_HISTORY_RECORD_BYTES else b""
                oversized = len(parts[0]) > MAX_HISTORY_RECORD_BYTES
            elif candidate is None:
                suffix = b""
                oversized = True
            else:
                suffix = candidate
                oversized = False
        # Si el límite de lectura cae en mitad de una línea, no se interpreta el
        # fragmento izquierdo como si fuera un registro completo.
        if position == 0 and suffix and not oversized:
            yield suffix

    @staticmethod
    def _decode_history_event(raw: bytes) -> dict | None:
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return event if isinstance(event, dict) else None

    def _rotate_history(
        self,
        descriptor: int,
        metadata: os.stat_result,
        record: bytes,
    ) -> tuple[tuple[int, int, int, int], int]:
        target_size = max(len(record), (self.history_max_bytes * 3) // 4)
        remaining = min(
            self.history_max_bytes - len(record),
            target_size - len(record),
        )
        recent: list[bytes] = []
        for raw in self._reverse_history_lines(
            descriptor,
            metadata.st_size,
            self.history_max_bytes,
        ):
            if len(recent) >= self.history_max_entries - 1:
                break
            if self._decode_history_event(raw) is None:
                continue
            line = raw + b"\n"
            if len(line) > remaining:
                break
            recent.append(line)
            remaining -= len(line)
        payload = b"".join(reversed(recent)) + record

        parent = self._history_parent()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory = os.open(parent, directory_flags)
        temporary_name = (
            f".history.jsonl.{os.getpid()}.{secrets.token_hex(8)}.new"
        )
        temporary = -1
        temporary_created = False
        replaced = False
        try:
            temporary_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            temporary_flags |= getattr(os, "O_CLOEXEC", 0)
            temporary = os.open(
                temporary_name,
                temporary_flags,
                0o600,
                dir_fd=directory,
            )
            temporary_created = True
            self._write_all(temporary, payload)
            os.fchmod(temporary, 0o600)
            os.fsync(temporary)
            current = os.stat(
                self.history_path.name,
                dir_fd=directory,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino)
                != (metadata.st_dev, metadata.st_ino)
            ):
                raise StateError("history.jsonl cambió durante la rotación")
            os.replace(
                temporary_name,
                self.history_path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            replaced = True
            os.fsync(directory)
            final = os.stat(
                self.history_path.name,
                dir_fd=directory,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(final.st_mode)
                or final.st_nlink != 1
                or final.st_size != len(payload)
                or stat.S_IMODE(final.st_mode) != 0o600
            ):
                raise StateError("la rotación del historial no cumplió su poscondición")
            return self._history_identity_for(final), len(recent) + 1
        except OSError as exc:
            raise StateError("no se pudo rotar history.jsonl de forma atómica") from exc
        finally:
            cleanup_error = None
            try:
                if temporary >= 0:
                    os.close(temporary)
                if temporary_created and not replaced:
                    try:
                        os.unlink(temporary_name, dir_fd=directory)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        cleanup_error = exc
            finally:
                os.close(directory)
            if cleanup_error is not None:
                raise StateError(
                    "no se pudo limpiar el temporal de rotación"
                ) from cleanup_error

    def _append_history(self, event: dict) -> None:
        record = (
            json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        if len(record) > min(MAX_HISTORY_RECORD_BYTES, self.history_max_bytes):
            raise StateError("el registro de historial supera el límite permitido")
        self._history_parent()
        descriptor = self._open_history(create=True)
        try:
            metadata = self._check_history_descriptor(descriptor)
            identity = self._history_identity_for(metadata)
            exceeds_byte_limit = (
                metadata.st_size + len(record) > self.history_max_bytes
            )
            if exceeds_byte_limit:
                # Un fichero heredado o manipulado puede ser arbitrariamente
                # grande: se rota desde la cola sin contarlo por completo.
                count = self.history_max_entries
            elif self._history_identity != identity or self._history_count is None:
                count = self._count_history_lines(descriptor, metadata.st_size)
            else:
                count = self._history_count
            rotate = (
                exceeds_byte_limit
                or count + 1 > self.history_max_entries
                or not self._history_ends_with_newline(descriptor, metadata.st_size)
            )
            if rotate:
                identity, count = self._rotate_history(
                    descriptor, metadata, record
                )
            else:
                self._write_all(descriptor, record)
                os.fsync(descriptor)
                final = self._check_history_descriptor(descriptor)
                if final.st_size != metadata.st_size + len(record):
                    raise StateError("history.jsonl cambió durante la escritura")
                identity = self._history_identity_for(final)
                count += 1
            self._history_identity = identity
            self._history_count = count
        except OSError as exc:
            raise StateError("no se pudo escribir history.jsonl de forma segura") from exc
        finally:
            os.close(descriptor)

    def _write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
        try:
            temporary.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _read_json(path: Path) -> dict | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def last_result(self, instance_id: str) -> dict | None:
        return self._read_json(self._result_path(instance_id))

    def remember_result(self, instance_id: str, result: dict) -> dict:
        event = {
            "format": 1,
            "at": self.now(),
            "node": self.node,
            "instance": instance_id,
            "result": result,
        }
        with self._lock:
            self._write_json(self._result_path(instance_id), event)
            self._append_history(event)
        return event

    def content(self, instance_id: str) -> dict | None:
        return self._read_json(self._content_path(instance_id))

    def remember_content(
        self,
        instance_id: str,
        fingerprint: str,
        source_node: str,
        role: str,
        *,
        parent_fingerprint: str | None = None,
        confirmed_fingerprint: str | None = None,
        ancestor_fingerprints: list[str] | None = None,
    ) -> dict:
        ancestors = []
        for value in ancestor_fingerprints or []:
            if isinstance(value, str) and value and value != fingerprint and value not in ancestors:
                ancestors.append(value)
        payload = {
            "format": 2,
            "instance": instance_id,
            "fingerprint": fingerprint,
            "confirmed_fingerprint": confirmed_fingerprint,
            "parent_fingerprint": parent_fingerprint,
            "ancestor_fingerprints": ancestors[:64],
            "source_node": source_node,
            "role": role,
            "updated_at": self.now(),
        }
        with self._lock:
            self._write_json(self._content_path(instance_id), payload)
        return payload

    def provisioning(self, transaction: str) -> dict | None:
        return self._read_json(self._provisioning_path(transaction))

    def remember_provisioning(self, transaction: str, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("el estado de provisión debe ser un objeto")
        record = {
            **payload,
            "format": 1,
            "transaction": transaction,
            "node": self.node,
            "updated_at": self.now(),
        }
        with self._lock:
            self._write_json(self._provisioning_path(transaction), record)
        return record

    def history(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            descriptor = self._open_history(create=False)
            if descriptor < 0:
                return []
            try:
                metadata = self._check_history_descriptor(descriptor)
                result = []
                for raw in self._reverse_history_lines(
                    descriptor,
                    metadata.st_size,
                    self.history_max_bytes,
                ):
                    event = self._decode_history_event(raw)
                    if event is not None:
                        result.append(event)
                        if len(result) >= limit:
                            break
                final = os.fstat(descriptor)
                if (
                    final.st_dev,
                    final.st_ino,
                    final.st_size,
                    final.st_mtime_ns,
                ) != self._history_identity_for(metadata):
                    raise StateError("history.jsonl cambió durante la lectura")
                return result
            except OSError as exc:
                raise StateError("no se pudo leer history.jsonl de forma segura") from exc
            finally:
                os.close(descriptor)

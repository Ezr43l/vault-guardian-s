import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "app"))

import snapshot
from config import Instance


TOKEN = "test-token-that-is-long-enough-for-vault-guardian"


def encrypted_package(
    manifest: dict, members: list[tuple[str, bytes | None]]
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        encoded = json.dumps(manifest).encode("utf-8")
        item = tarfile.TarInfo("manifest.json")
        item.size = len(encoded)
        archive.addfile(item, io.BytesIO(encoded))
        for name, payload in members:
            item = tarfile.TarInfo(name)
            if payload is None:
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
                continue
            item.size = len(payload)
            archive.addfile(item, io.BytesIO(payload))
    return snapshot._fernet(TOKEN).encrypt(stream.getvalue())


def manifest_for(files: dict[str, bytes]) -> dict:
    return {
        "format": 1,
        "instance": "instance",
        "source_node": "node-1",
        "created_at": "2026-08-30T00:00:00Z",
        "managed": ["config.json", "attachments", "sends"],
        "include_sends": True,
        "entries": [
            {
                "path": name,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for name, payload in files.items()
        ],
        "parent_fingerprint": None,
        "ancestor_fingerprints": [],
    }


def pax_record(key: str, value: str) -> bytes:
    body = f"{key}={value}\n".encode("utf-8")
    size = len(body) + 2
    while True:
        record = str(size).encode("ascii") + b" " + body
        if len(record) == size:
            return record
        size = len(record)


def make_instance(root: Path, name: str) -> Instance:
    data = root / name
    data.mkdir()
    connection = sqlite3.connect(data / "db.sqlite3")
    connection.execute("create table values_table (value text)")
    connection.execute("insert into values_table values ('original')")
    connection.commit()
    connection.close()
    (data / "config.json").write_text('{"setting":"same"}', encoding="utf-8")
    (data / "rsa_key.pem").write_text("jwt-key", encoding="utf-8")
    (data / "attachments").mkdir()
    (data / "attachments" / "a").write_bytes(b"attachment")
    (data / "sends").mkdir()
    return Instance(name, "container-" + name, data, 8000, "/api/version", name)


class SnapshotTests(unittest.TestCase):
    def test_round_trip_uses_consistent_database_and_managed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            destination_root = root / "destination"
            source_root.mkdir()
            destination_root.mkdir()
            source = make_instance(source_root, "instance")
            destination = make_instance(destination_root, "instance")
            (source.data_dir / "sends" / "s").write_bytes(b"send")
            (destination.data_dir / "attachments" / "stale").write_bytes(b"stale")
            (destination.data_dir / "sends" / "stale").write_bytes(b"stale")
            package = root / "package.vgb"

            info = snapshot.create_snapshot(source, "nodo-1", TOKEN, package)
            self.assertEqual(info["manifest"]["source_node"], "nodo-1")
            paths = {entry["path"] for entry in info["manifest"]["entries"]}
            self.assertIn("data/attachments/a", paths)
            self.assertIn("data/sends/s", paths)

            result = snapshot.apply_snapshot(destination, package.read_bytes(), TOKEN,
                                              10 * 1024 * 1024)
            self.assertEqual(result["source_node"], "nodo-1")
            self.assertFalse((destination.data_dir / "attachments" / "stale").exists())
            self.assertEqual((destination.data_dir / "attachments" / "a").read_bytes(), b"attachment")
            self.assertFalse((destination.data_dir / "sends" / "stale").exists())
            self.assertEqual(
                (destination.data_dir / "sends" / "s").read_bytes(), b"send"
            )
            for name in ("db.sqlite3", "config.json", "rsa_key.pem"):
                mode = stat.S_IMODE((destination.data_dir / name).stat().st_mode)
                self.assertEqual(0o600, mode)
            self.assertEqual(
                0o600,
                stat.S_IMODE(
                    (destination.data_dir / "attachments" / "a").stat().st_mode
                ),
            )
            for name in ("attachments", "sends"):
                mode = stat.S_IMODE((destination.data_dir / name).stat().st_mode)
                self.assertEqual(0o700, mode)
            check = sqlite3.connect(destination.data_dir / "db.sqlite3")
            self.assertEqual(check.execute("select value from values_table").fetchone()[0], "original")
            check.close()

    def test_duplicate_paths_and_excessive_member_counts_are_rejected(self):
        database = b"sqlite-placeholder"
        manifest = manifest_for({"data/db.sqlite3": database})
        duplicate = encrypted_package(
            manifest,
            [("data/db.sqlite3", database), ("data/db.sqlite3", database)],
        )
        with self.assertRaisesRegex(snapshot.SnapshotError, "duplicadas"):
            snapshot.read_manifest(duplicate, TOKEN, 10 * 1024 * 1024)

        normal = encrypted_package(
            manifest, [("data/db.sqlite3", database)])
        with mock.patch.object(snapshot, "MAX_ARCHIVE_MEMBERS", 1):
            with self.assertRaisesRegex(snapshot.SnapshotError, "demasiados"):
                snapshot.read_manifest(normal, TOKEN, 10 * 1024 * 1024)

    def test_manifest_contract_and_directories_are_exact(self):
        database = b"sqlite-placeholder"
        manifest = manifest_for({"data/db.sqlite3": database})

        incomplete = json.loads(json.dumps(manifest))
        del incomplete["created_at"]
        package = encrypted_package(
            incomplete, [("data/db.sqlite3", database)])
        with self.assertRaisesRegex(snapshot.SnapshotError, "incompletos"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

        extra_entry_field = json.loads(json.dumps(manifest))
        extra_entry_field["entries"][0]["ignored"] = True
        package = encrypted_package(
            extra_entry_field, [("data/db.sqlite3", database)])
        with self.assertRaisesRegex(snapshot.SnapshotError, "entrada no válida"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

        package = encrypted_package(
            manifest,
            [("data/db.sqlite3", database), ("data/not-declared", None)],
        )
        with self.assertRaisesRegex(snapshot.SnapshotError, "directorios"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

    def test_manifest_rejects_files_outside_the_exact_content_contract(self):
        database = b"sqlite-placeholder"
        cases = (
            ("data/ignored", True),
            ("data/nested/rsa_key.pem", True),
            ("data/sends/send-id", False),
        )
        for path, include_sends in cases:
            with self.subTest(path=path, include_sends=include_sends):
                files = {"data/db.sqlite3": database, path: b"unexpected"}
                manifest = manifest_for(files)
                manifest["include_sends"] = include_sends
                package = encrypted_package(manifest, list(files.items()))
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "ruta no válida"
                ):
                    snapshot.read_manifest(
                        package, TOKEN, 10 * 1024 * 1024
                    )

    def test_manifest_and_unpacked_data_have_hard_limits(self):
        database = b"x" * 64
        package = encrypted_package(
            manifest_for({"data/db.sqlite3": database}),
            [("data/db.sqlite3", database)],
        )
        with mock.patch.object(snapshot, "MAX_MANIFEST_BYTES", 32):
            with self.assertRaisesRegex(snapshot.SnapshotError, "manifest.json"):
                snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)
        with mock.patch.object(snapshot, "MAX_UNPACKED_BYTES", 32):
            with self.assertRaisesRegex(snapshot.SnapshotError, "sin comprimir"):
                snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)
        with mock.patch.object(snapshot, "MAX_ARCHIVE_METADATA_BYTES", 1):
            with self.assertRaisesRegex(snapshot.SnapshotError, "metadatos TAR agregados"):
                snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

    def test_directory_payloads_and_oversized_tar_metadata_are_rejected(self):
        database = b"sqlite-placeholder"
        manifest = manifest_for({"data/db.sqlite3": database})

        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            encoded = json.dumps(manifest).encode("utf-8")
            item = tarfile.TarInfo("manifest.json")
            item.size = len(encoded)
            archive.addfile(item, io.BytesIO(encoded))
            item = tarfile.TarInfo("data/db.sqlite3")
            item.size = len(database)
            archive.addfile(item, io.BytesIO(database))
            directory = tarfile.TarInfo("data/attachments")
            directory.type = tarfile.DIRTYPE
            directory.size = 7
            archive.addfile(directory, io.BytesIO(b"payload"))
        package = snapshot._fernet(TOKEN).encrypt(stream.getvalue())
        with self.assertRaisesRegex(snapshot.SnapshotError, "directorio.*tamaño"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            encoded = json.dumps(manifest).encode("utf-8")
            item = tarfile.TarInfo("manifest.json")
            item.size = len(encoded)
            archive.addfile(item, io.BytesIO(encoded))
            item = tarfile.TarInfo("data/db.sqlite3")
            item.size = len(database)
            item.pax_headers = {
                "comment": "x" * (snapshot.MAX_ARCHIVE_PAX_BYTES + 1)
            }
            archive.addfile(item, io.BytesIO(database))
        package = snapshot._fernet(TOKEN).encrypt(stream.getvalue())
        with self.assertRaisesRegex(snapshot.SnapshotError, "metadatos.*demasiado grandes"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

    def test_deep_content_paths_and_hidden_metadata_chains_are_rejected(self):
        database = b"sqlite-placeholder"
        deep_path = "data/attachments/" + "/".join(
            ["nested"] * snapshot.MAX_ARCHIVE_DEPTH + ["payload"]
        )
        files = {"data/db.sqlite3": database, deep_path: b"deep"}
        package = encrypted_package(manifest_for(files), list(files.items()))
        with self.assertRaisesRegex(snapshot.SnapshotError, "profundidad"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            payload = pax_record("comment", "bounded")
            for _ in range(snapshot.MAX_ARCHIVE_DEPTH + 1):
                item = tarfile.TarInfo("pax-header")
                item.type = tarfile.XHDTYPE
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            encoded = json.dumps(
                manifest_for({"data/db.sqlite3": database})
            ).encode("utf-8")
            item = tarfile.TarInfo("manifest.json")
            item.size = len(encoded)
            archive.addfile(item, io.BytesIO(encoded))
            item = tarfile.TarInfo("data/db.sqlite3")
            item.size = len(database)
            archive.addfile(item, io.BytesIO(database))
        package = snapshot._fernet(TOKEN).encrypt(stream.getvalue())
        with self.assertRaisesRegex(snapshot.SnapshotError, "profundidad"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

    def test_every_extracted_hash_and_sqlite_integrity_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination_root = root / "destination"
            destination_root.mkdir()
            destination = make_instance(destination_root, "instance")
            invalid_database = b"this is not a sqlite database"
            manifest = manifest_for({"data/db.sqlite3": invalid_database})

            wrong_hash = json.loads(json.dumps(manifest))
            wrong_hash["entries"][0]["sha256"] = "0" * 64
            package = encrypted_package(
                wrong_hash, [("data/db.sqlite3", invalid_database)])
            with self.assertRaisesRegex(snapshot.SnapshotError, "hash incorrecto"):
                snapshot.apply_snapshot(
                    destination, package, TOKEN, 10 * 1024 * 1024)

            package = encrypted_package(
                manifest, [("data/db.sqlite3", invalid_database)])
            with self.assertRaisesRegex(snapshot.SnapshotError, "SQLite"):
                snapshot.apply_snapshot(
                    destination, package, TOKEN, 10 * 1024 * 1024)
            check = sqlite3.connect(destination.data_dir / "db.sqlite3")
            self.assertEqual(
                check.execute("select value from values_table").fetchone()[0],
                "original",
            )
            check.close()

    def test_invalid_manifest_never_changes_the_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination_root = root / "destination"
            destination_root.mkdir()
            destination = make_instance(destination_root, "instance")
            database = b"replacement"
            manifest = manifest_for({"data/db.sqlite3": database})
            del manifest["created_at"]
            package = encrypted_package(
                manifest, [("data/db.sqlite3", database)])
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.apply_snapshot(
                    destination, package, TOKEN, 10 * 1024 * 1024)

            manifest = manifest_for({"data/db.sqlite3": database})
            manifest["include_sends"] = False
            package = encrypted_package(
                manifest, [("data/db.sqlite3", database)])
            with self.assertRaisesRegex(snapshot.SnapshotError, "include_sends"):
                snapshot.apply_snapshot(
                    destination, package, TOKEN, 10 * 1024 * 1024)
            check = sqlite3.connect(destination.data_dir / "db.sqlite3")
            self.assertEqual(
                check.execute("select value from values_table").fetchone()[0],
                "original",
            )
            check.close()

    def test_restore_removes_stale_files_and_links_for_absent_managed_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            destination_root = root / "destination"
            source_root.mkdir()
            destination_root.mkdir()
            source = make_instance(source_root, "instance")
            destination = make_instance(destination_root, "instance")
            (source.data_dir / "attachments" / "a").unlink()
            (source.data_dir / "attachments").rmdir()
            (source.data_dir / "sends").rmdir()
            package = root / "package.vgb"
            snapshot.create_snapshot(source, "node-1", TOKEN, package)

            (destination.data_dir / "attachments" / "a").unlink()
            (destination.data_dir / "attachments").rmdir()
            (destination.data_dir / "attachments").write_bytes(b"stale")
            (destination.data_dir / "sends").rmdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "must-remain").write_bytes(b"safe")
            os.symlink(outside, destination.data_dir / "sends")

            snapshot.apply_snapshot(
                destination, package.read_bytes(), TOKEN, 10 * 1024 * 1024
            )

            with self.assertRaises(FileNotFoundError):
                (destination.data_dir / "attachments").lstat()
            with self.assertRaises(FileNotFoundError):
                (destination.data_dir / "sends").lstat()
            self.assertEqual(b"safe", (outside / "must-remain").read_bytes())

    def test_restore_fails_closed_if_a_managed_tree_cannot_be_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            destination_root = root / "destination"
            source_root.mkdir()
            destination_root.mkdir()
            source = make_instance(source_root, "instance")
            destination = make_instance(destination_root, "instance")
            (source.data_dir / "attachments" / "a").unlink()
            (source.data_dir / "attachments").rmdir()
            package = root / "package.vgb"
            snapshot.create_snapshot(source, "node-1", TOKEN, package)

            with mock.patch.object(
                snapshot.shutil, "rmtree", side_effect=OSError("denied")
            ):
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "no se pudo aplicar.*OSError"
                ):
                    snapshot.apply_snapshot(
                        destination,
                        package.read_bytes(),
                        TOKEN,
                        10 * 1024 * 1024,
                    )
            self.assertTrue((destination.data_dir / "attachments").is_dir())

    def test_snapshot_creation_limits_source_size_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            source_root.mkdir()
            source = make_instance(source_root, "instance")
            package = root / "package.vgb"
            with mock.patch.object(snapshot, "MAX_UNPACKED_BYTES", 1):
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "sin comprimir"
                ):
                    snapshot.create_snapshot(
                        source, "node-1", TOKEN, package, 10 * 1024 * 1024)

            os.symlink("a", source.data_dir / "attachments" / "link")
            with self.assertRaisesRegex(snapshot.SnapshotError, "simbólicos"):
                snapshot.create_snapshot(
                    source, "node-1", TOKEN, package, 10 * 1024 * 1024)

            (source.data_dir / "attachments" / "link").unlink()
            database = source.data_dir / "db.sqlite3"
            real_database = source.data_dir / "real.sqlite3"
            database.replace(real_database)
            os.symlink(real_database.name, database)
            with self.assertRaisesRegex(snapshot.SnapshotError, "simbólicos|base SQLite"):
                snapshot.create_snapshot(
                    source, "node-1", TOKEN, package, 10 * 1024 * 1024)

    def test_atomic_file_replacement_never_follows_a_stale_temporary_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            target = root / "target"
            victim = root / "victim"
            source.write_bytes(b"replacement")
            target.write_bytes(b"old")
            victim.write_bytes(b"must-not-change")
            temporary = root / ".target.vault-guardian-new"
            os.symlink(victim.name, temporary)

            snapshot._replace_file(source, target)

            self.assertEqual(b"replacement", target.read_bytes())
            self.assertEqual(b"must-not-change", victim.read_bytes())
            self.assertFalse(temporary.exists())

    def test_atomic_file_replacement_cleans_temporary_after_copy_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            target = root / "target"
            temporary = root / ".target.vault-guardian-new"
            source.write_bytes(b"replacement")
            target.write_bytes(b"old")

            with mock.patch.object(
                snapshot.shutil, "copyfileobj", side_effect=OSError("copy failed")
            ):
                with self.assertRaises(OSError):
                    snapshot._replace_file(source, target)

            self.assertEqual(b"old", target.read_bytes())
            self.assertFalse(temporary.exists())

    def test_snapshot_output_replaces_a_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            source_root.mkdir()
            source = make_instance(source_root, "instance")
            victim = root / "victim"
            victim.write_bytes(b"must-not-change")
            package = root / "package.vgb"
            os.symlink(victim, package)

            snapshot.create_snapshot(
                source, "node-1", TOKEN, package, 10 * 1024 * 1024
            )

            self.assertFalse(package.is_symlink())
            self.assertEqual(b"must-not-change", victim.read_bytes())
            self.assertEqual(
                "instance",
                snapshot.read_manifest(
                    package.read_bytes(), TOKEN, 10 * 1024 * 1024
                )[0]["instance"],
            )

    def test_snapshot_creation_rejects_a_same_size_source_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            source_root.mkdir()
            source = make_instance(source_root, "instance")
            package = root / "package.vgb"
            config = source.data_dir / "config.json"
            metadata = config.stat()
            original_read = snapshot.os.read
            mutated = False

            def read_then_mutate(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                block = original_read(descriptor, size)
                opened = os.fstat(descriptor)
                if opened.st_ino == metadata.st_ino and not mutated:
                    replacement = b'{"setting":"evil"}'
                    self.assertEqual(config.stat().st_size, len(replacement))
                    config.write_bytes(replacement)
                    mutated = True
                return block

            with mock.patch.object(
                snapshot.os, "read", side_effect=read_then_mutate
            ):
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "cambió durante la captura"
                ):
                    snapshot.create_snapshot(
                        source, "node-1", TOKEN, package, 10 * 1024 * 1024)
            self.assertTrue(mutated)
            self.assertFalse(package.exists())

    def test_snapshot_capture_never_follows_a_source_symlink_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            source_root.mkdir()
            source = make_instance(source_root, "instance")
            package = root / "package.vgb"
            config = source.data_dir / "config.json"
            original = source.data_dir / "config.original"
            victim = root / "request.json"
            victim.write_text('{"token":"must-not-leak"}', encoding="utf-8")
            original_stat = snapshot.os.stat
            swapped = False

            def stat_then_swap(path, *args, **kwargs):
                nonlocal swapped
                result = original_stat(path, *args, **kwargs)
                if path == "config.json" and kwargs.get("dir_fd") is not None and not swapped:
                    config.rename(original)
                    os.symlink(victim, config)
                    swapped = True
                return result

            with mock.patch.object(
                snapshot.os, "stat", side_effect=stat_then_swap
            ):
                with self.assertRaises(snapshot.SnapshotError):
                    snapshot.create_snapshot(
                        source, "node-1", TOKEN, package, 10 * 1024 * 1024
                    )
            self.assertTrue(swapped)
            self.assertFalse(package.exists())
            self.assertEqual(
                '{"token":"must-not-leak"}', victim.read_text(encoding="utf-8")
            )

    def test_source_capture_enforces_size_while_copying_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_bytes(b"four")
            destination = root / "captured"
            descriptor = snapshot._open_source_directory(root)
            try:
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "límite de seguridad"
                ):
                    snapshot._capture_source_file(
                        descriptor, "source", destination, 3
                    )
            finally:
                os.close(descriptor)
            self.assertFalse(destination.exists())

    def test_only_local_backup_refresh_accepts_an_old_authenticated_package(self):
        database = b"sqlite-placeholder"
        current = encrypted_package(
            manifest_for({"data/db.sqlite3": database}),
            [("data/db.sqlite3", database)],
        )
        raw = snapshot._fernet(TOKEN).decrypt(current)
        old = snapshot._fernet(TOKEN).encrypt_at_time(
            raw, int(time.time()) - 901
        )

        with self.assertRaisesRegex(snapshot.SnapshotError, "caducado"):
            snapshot.read_manifest(old, TOKEN, 10 * 1024 * 1024)
        manifest, refreshed = snapshot.refresh_backup(
            old, TOKEN, 10 * 1024 * 1024
        )
        self.assertEqual("instance", manifest["instance"])
        self.assertEqual(
            "instance",
            snapshot.read_manifest(
                refreshed, TOKEN, 10 * 1024 * 1024
            )[0]["instance"],
        )

        with self.assertRaises(snapshot.SnapshotError):
            snapshot.refresh_backup(
                old,
                "different-token-that-is-also-long-enough-for-the-test",
                10 * 1024 * 1024,
            )
        corrupted = bytearray(old)
        corrupted[len(corrupted) // 2] ^= 1
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.refresh_backup(
                bytes(corrupted), TOKEN, 10 * 1024 * 1024
            )

    def test_path_traversal_is_rejected(self):
        database = b"sqlite-placeholder"
        manifest = manifest_for({"data/db.sqlite3": database})
        package = encrypted_package(
            manifest,
            [("data/db.sqlite3", database), ("data/../outside", b"x")],
        )
        with self.assertRaisesRegex(snapshot.SnapshotError, "ruta peligrosa"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)

        for path in ("data/attachments/bad\x00name", "data/attachments/bad\nname"):
            with self.subTest(path=repr(path)):
                with self.assertRaisesRegex(snapshot.SnapshotError, "peligrosa"):
                    snapshot._safe_member(path)

    def test_links_and_special_archive_members_are_rejected(self):
        database = b"sqlite-placeholder"
        manifest = manifest_for({"data/db.sqlite3": database})
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            encoded = json.dumps(manifest).encode("utf-8")
            item = tarfile.TarInfo("manifest.json")
            item.size = len(encoded)
            archive.addfile(item, io.BytesIO(encoded))
            item = tarfile.TarInfo("data/db.sqlite3")
            item.size = len(database)
            archive.addfile(item, io.BytesIO(database))
            link = tarfile.TarInfo("data/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "db.sqlite3"
            archive.addfile(link)
        package = snapshot._fernet(TOKEN).encrypt(stream.getvalue())
        with self.assertRaisesRegex(snapshot.SnapshotError, "enlace no aceptado"):
            snapshot.read_manifest(package, TOKEN, 10 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

import json
import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path

import data_access
import snapshot
from config import Instance


TOKEN = "replication-password-with-at-least-32-characters"


class FakeDocker:
    def __init__(self, managed_root: Path, host_root: str = "/srv/appdata"):
        self.managed_root = managed_root
        self.host_root = host_root
        self.targets = {
            "vaultwarden-source": "/srv/appdata/vaultwarden-source",
        }

    def inspect_full(self, container):
        if container == socket.gethostname() or container == "guardian-id":
            return {
                "Mounts": [{
                    "Type": "bind",
                    "Source": self.host_root,
                    "Destination": str(self.managed_root),
                    "RW": True,
                }],
            }
        source = self.targets.get(container)
        if source:
            return {
                "Mounts": [{
                    "Type": "bind",
                    "Source": source,
                    "Destination": "/data",
                    "RW": True,
                }],
            }
        return None

    def containers(self):
        return [{
            "Id": "guardian-id",
            "Labels": {"com.vault-guardian.role": "app"},
        }]


class ContainerDataTests(unittest.TestCase):
    @staticmethod
    def instance(data_dir: Path, *, backend: str = "auto") -> Instance:
        return Instance(
            id="vaultwarden-source",
            display_name="Vaultwarden 1",
            container="vaultwarden-source",
            data_dir=data_dir,
            health_port=8080,
            health_path="/alive",
            floating_service="vaultwarden-source",
            include_sends=True,
            replication_enabled=True,
            data_backend=backend,
        )

    @staticmethod
    def create_data(root: Path, marker: str = "source") -> None:
        root.mkdir(parents=True)
        database = sqlite3.connect(root / "db.sqlite3")
        database.execute("CREATE TABLE sample (value TEXT)")
        database.execute("INSERT INTO sample VALUES (?)", (marker,))
        database.commit()
        database.close()
        (root / "config.json").write_text(
            json.dumps({"marker": marker}), encoding="utf-8")
        attachments = root / "attachments"
        attachments.mkdir()
        (attachments / "item.bin").write_bytes(marker.encode("utf-8"))

    def test_snapshot_uses_mounted_root_without_helper_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            data_dir = root / "vaultwarden-source"
            self.create_data(data_dir)
            docker = FakeDocker(root)
            access = data_access.ContainerData(docker, root)
            output = Path(temporary) / "snapshot.vgb"

            result = access.create_snapshot(
                self.instance(data_dir), "node-1", TOKEN, output,
                8 * 1024 * 1024,
            )

            self.assertTrue(output.is_file())
            self.assertEqual("vaultwarden-source", result["manifest"]["instance"])
            self.assertEqual("direct", access.backend(self.instance(data_dir)))
            self.assertTrue(access.mount_available())

    def test_apply_replaces_managed_content_through_existing_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            self.create_data(source, "new")
            package = base / "source.vgb"
            snapshot.create_snapshot(
                self.instance(source), "node-1", TOKEN, package,
                8 * 1024 * 1024,
            )

            root = base / "instances"
            destination = root / "vaultwarden-source"
            self.create_data(destination, "old")
            (destination / "attachments" / "obsolete.bin").write_bytes(b"old")
            docker = FakeDocker(root)
            access = data_access.ContainerData(docker, root)

            result = access.apply_snapshot(
                self.instance(destination), package.read_bytes(), TOKEN,
                8 * 1024 * 1024,
            )

            self.assertTrue(result["ok"])
            self.assertFalse(
                (destination / "attachments" / "obsolete.bin").exists())
            database = sqlite3.connect(destination / "db.sqlite3")
            try:
                value = database.execute("SELECT value FROM sample").fetchone()[0]
            finally:
                database.close()
            self.assertEqual("new", value)

    def test_docker_backend_maps_legacy_logical_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            destination = root / "vaultwarden-source"
            self.create_data(destination)
            access = data_access.ContainerData(FakeDocker(root), root)
            legacy = self.instance(root / ".docker" / "vaultwarden-source",
                                   backend="docker")

            self.assertEqual("direct", access.backend(legacy))

    def test_rejects_configured_path_that_does_not_match_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            destination = root / "vaultwarden-source"
            destination.mkdir(parents=True)
            access = data_access.ContainerData(FakeDocker(root), root)
            wrong = self.instance(root / "another-directory")

            with self.assertRaisesRegex(
                data_access.DataAccessError, "no corresponde al volumen /data"
            ):
                access.backend(wrong)

    def test_refuses_non_bind_data_volume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            root.mkdir()
            docker = FakeDocker(root)
            docker.inspect_full = lambda _container: {
                "Mounts": [{
                    "Type": "volume",
                    "Source": "/var/lib/docker/volumes/unsafe",
                    "Destination": "/data",
                    "RW": True,
                }]
            }
            access = data_access.ContainerData(docker, root)

            with self.assertRaisesRegex(
                data_access.DataAccessError, "carpeta host escribible"
            ):
                access.backend(self.instance(root / "vaultwarden-source"))

    def test_refuses_target_outside_mounted_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            root.mkdir()
            docker = FakeDocker(root)
            docker.targets["vaultwarden-source"] = "/srv/other/vaultwarden"
            access = data_access.ContainerData(docker, root)

            with self.assertRaisesRegex(
                data_access.DataAccessError, "fuera de la raíz montada"
            ):
                access.backend(self.instance(root / "vaultwarden-source"))

    def test_read_only_guardian_mount_is_not_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            root.mkdir()
            docker = FakeDocker(root)
            original = docker.inspect_full

            def inspect(container):
                result = original(container)
                if container == socket.gethostname():
                    result["Mounts"][0]["RW"] = False
                return result

            docker.inspect_full = inspect
            access = data_access.ContainerData(docker, root)

            self.assertFalse(access.mount_available())

    def test_target_directory_is_reused_or_created_inside_the_mounted_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            root.mkdir()
            access = data_access.ContainerData(FakeDocker(root), root)
            existing = root / "existing-vault"
            existing.mkdir()

            state = access.check_target_directory(
                "/srv/appdata/existing-vault")
            self.assertTrue(state["exists"])
            self.assertFalse(access.prepare_target_directory(
                "/srv/appdata/existing-vault"))

            self.assertTrue(access.prepare_target_directory(
                "/srv/appdata/new-vault"))
            self.assertTrue((root / "new-vault").is_dir())
            access.discard_created_target("/srv/appdata/new-vault")
            self.assertFalse((root / "new-vault").exists())

    def test_target_directory_refuses_data_and_paths_outside_the_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "instances"
            occupied = root / "occupied"
            occupied.mkdir(parents=True)
            (occupied / "db.sqlite3").write_bytes(b"existing")
            access = data_access.ContainerData(FakeDocker(root), root)

            with self.assertRaisesRegex(
                data_access.DataAccessError, "contiene datos"
            ):
                access.check_target_directory("/srv/appdata/occupied")
            with self.assertRaisesRegex(
                data_access.DataAccessError, "fuera de la raíz montada"
            ):
                access.check_target_directory("/mnt/cache/appdata/new-vault")


if __name__ == "__main__":
    unittest.main()

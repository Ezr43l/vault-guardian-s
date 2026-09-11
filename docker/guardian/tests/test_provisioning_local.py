import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import provisioning
import provisioning_local
import sealed
from state import StateStore


TOKEN = "shared-provisioning-password-with-at-least-32-characters"


class FakeDocker:
    def __init__(self):
        self.items = {}
        self.pulled = []
        self.created = []
        self.removed = []
        self.started = []
        self.stopped = []

    def containers(self):
        return [
            {"Names": ["/" + name], "Id": name}
            for name in sorted(self.items)
        ]

    def inspect_full(self, name):
        return self.items.get(name)

    def inspect_image(self, image):
        return None

    def pull_image(self, image):
        self.pulled.append(image)

    def create_container(self, name, spec):
        self.created.append((name, spec))
        source, destination, _mode = spec["HostConfig"]["Binds"][0].rsplit(":", 2)
        self.items[name] = {
            "Name": "/" + name,
            "Config": {
                "Image": spec["Image"],
                "Env": spec["Env"],
                "Labels": spec["Labels"],
            },
            "HostConfig": spec["HostConfig"],
            "Mounts": [{
                "Type": "bind",
                "Source": source,
                "Destination": destination,
                "RW": True,
            }],
            "State": {"Running": False},
        }
        return "created-id"

    def remove(self, name, *, force=False):
        self.removed.append((name, force))
        self.items.pop(name, None)

    def start(self, name):
        self.started.append(name)
        self.items[name]["State"]["Running"] = True

    def stop(self, name, timeout=15):
        self.stopped.append(name)
        self.items[name]["State"]["Running"] = False


class FakeData:
    def __init__(self, empty=True):
        self.empty = empty
        self.applied = []
        self.prepared_targets = []
        self.discarded_targets = []

    def check_target_directory(self, target_path):
        if not self.empty:
            raise provisioning_local.data_access.DataAccessError(
                "la carpeta de destino contiene datos y no se sobrescribirá")
        return {"exists": False, "empty": True, "will_create": True}

    def prepare_target_directory(self, target_path):
        self.check_target_directory(target_path)
        self.prepared_targets.append(target_path)
        return True

    def discard_created_target(self, target_path):
        self.discarded_targets.append(target_path)

    def inspect_data(self, instance, token, max_bytes):
        return {
            "empty": self.empty,
            "entries": [] if self.empty else ["db.sqlite3"],
            "truncated": False,
            "backend": "docker",
        }

    def apply_snapshot(self, instance, payload, token, max_bytes):
        self.applied.append((instance, payload, token, max_bytes))
        return {"ok": True, "created_at": "2026-08-25T12:00:00Z"}


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class LocalProvisionerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.settings = SimpleNamespace(
            replication_token=TOKEN,
            vaultwarden_root="/mnt/user/appdata",
            data_roots=(root / "instances",),
            node="node-2",
            node_ip="192.0.2.12",
            max_package_bytes=16 * 1024 * 1024,
            # Peer/floating HTTP remains disabled; the Vaultwarden health probe is
            # an independent, uncredentialed internal channel.
            allow_insecure_http=False,
            ca_file=None,
        )
        self.docker = FakeDocker()
        self.data = FakeData()
        self.state = StateStore(root / "state", "node-2")
        self.provisioner = provisioning_local.LocalProvisioner(
            self.settings, self.docker, self.data, self.state)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def source():
        return provisioning.VaultwardenSpec(
            container="vaultwarden-1",
            display_image="vaultwarden/server:latest",
            pinned_image="vaultwarden/server@sha256:" + "a" * 64,
            host_port=8080,
            data_source="/source",
            environment=(
                "ADMIN_TOKEN=very-secret-value",
                "SIGNUPS_ALLOWED=false",
            ),
            running=True,
        )

    def envelope(self):
        return sealed.seal({
            "transaction": "provision:12345678",
            "source": self.source().private(),
            "instance_id": "vaultwarden-1",
            "display_name": "Vaultwarden 1",
            "data_directory": "vaultwarden-1",
            "target_path": "/mnt/user/appdata/vaultwarden-1",
            "health_path": "/alive",
            "include_sends": True,
            "source_node": "node-1",
        }, TOKEN, "provisioning-spec")

    def test_prepares_applies_activates_and_persists_no_secret(self):
        preview = self.provisioner.preflight(self.envelope())
        self.assertEqual("validated", preview["stage"])

        prepared = self.provisioner.prepare(self.envelope())
        self.assertEqual("prepared", prepared["stage"])
        repeated = self.provisioner.prepare(self.envelope())
        self.assertTrue(repeated["repeated"])
        self.assertEqual(
            ["vaultwarden/server@sha256:" + "a" * 64],
            self.docker.pulled,
        )
        created_spec = self.docker.created[0][1]
        self.assertIn("ADMIN_TOKEN=very-secret-value", created_spec["Env"])
        self.assertEqual(
            ["/mnt/user/appdata/vaultwarden-1:/data:rw"],
            created_spec["HostConfig"]["Binds"],
        )
        self.assertEqual(
            ["/mnt/user/appdata/vaultwarden-1"],
            self.data.prepared_targets,
        )

        state_text = next(
            (Path(self.temporary.name) / "state" / "provisioning").glob("*.json")
        ).read_text(encoding="utf-8")
        self.assertNotIn("very-secret-value", state_text)

        applied = self.provisioner.apply_snapshot(
            "provision:12345678", b"encrypted-snapshot")
        self.assertEqual("data_applied", applied["stage"])
        self.assertEqual(b"encrypted-snapshot", self.data.applied[0][1])

        with mock.patch(
            "provisioning_local.http_client.request",
            return_value=provisioning_local.http_client.HttpResponse(200, b"{}"),
        ):
            activated = self.provisioner.activate(
                "provision:12345678", attempts=1)
        self.assertEqual("ready", activated["stage"])
        self.assertEqual("docker", activated["instance_config"]["data_backend"])
        registered = self.provisioner.mark_registered("provision:12345678")
        self.assertEqual("registered", registered["stage"])

    def test_nonempty_destination_is_never_overwritten(self):
        self.data.empty = False
        with self.assertRaisesRegex(
            provisioning_local.LocalProvisioningError, "no se sobrescribirá"
        ):
            self.provisioner.prepare(self.envelope())

        self.assertEqual([], self.docker.created)
        self.assertEqual([], self.docker.removed)
        record = self.state.provisioning("provision:12345678")
        self.assertEqual("preparation_failed", record["stage"])
        self.assertNotIn("entries", record)

    def test_port_collision_blocks_before_any_pull_or_create(self):
        self.docker.items["another-service"] = {
            "Name": "/another-service",
            "Config": {"Labels": {}},
            "HostConfig": {
                "PortBindings": {
                    "80/tcp": [{"HostIp": "", "HostPort": "8080"}],
                },
            },
            "Mounts": [],
        }
        with self.assertRaisesRegex(
            provisioning_local.LocalProvisioningError, "puerto 8080"
        ):
            self.provisioner.preflight(self.envelope())
        self.assertEqual([], self.docker.pulled)
        self.assertEqual([], self.docker.created)


if __name__ == "__main__":
    unittest.main()

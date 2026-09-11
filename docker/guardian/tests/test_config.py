import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from config import (
    ConfigError,
    Instance,
    Settings,
    disable_managed_token,
    write_instances,
    write_local_settings,
    write_managed_token,
    write_portal_access,
)


class ConfigTests(unittest.TestCase):
    def test_portal_access_is_editable_and_persisted_by_the_app(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir()
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8")
            with mock.patch.dict(os.environ, {"VG_STATE_DIR": str(state)}, clear=True):
                self.assertFalse(Settings.load(instances).allow_insecure_portal)
                write_portal_access(state, True)
                self.assertTrue(Settings.load(instances).allow_insecure_portal)
                self.assertEqual(
                    (state / "portal-access.json").stat().st_mode & 0o777, 0o600)
            with mock.patch.dict(os.environ, {
                "VG_STATE_DIR": str(state),
                "VG_ALLOW_INSECURE_PORTAL": "false",
            }, clear=True):
                self.assertTrue(Settings.load(instances).allow_insecure_portal)
                write_portal_access(state, False)
                self.assertFalse(Settings.load(instances).allow_insecure_portal)

    def test_session_and_history_move_from_environment_to_editable_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8")
            environment = {
                "VG_STATE_DIR": str(state),
                "VG_DATA_ROOTS": str(state),
                "VG_SESSION_MINUTES": "45",
                "VG_HISTORY_MAX_MB": "32",
                "VG_HISTORY_MAX_ENTRIES": "8000",
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                legacy = Settings.load(instances)
                self.assertEqual(legacy.session_minutes, 45)
                self.assertEqual(legacy.history_max_bytes, 32 * 1024 * 1024)
                self.assertEqual(legacy.history_max_entries, 8000)
                write_local_settings(state, {
                    "session_minutes": 90,
                    "history_max_mb": 24,
                    "history_max_entries": 6000,
                })
                editable = Settings.load(instances)
            self.assertEqual(editable.session_minutes, 90)
            self.assertEqual(editable.history_max_bytes, 24 * 1024 * 1024)
            self.assertEqual(editable.history_max_entries, 6000)
            self.assertEqual(
                (state / "application-settings.json").stat().st_mode & 0o777,
                0o600,
            )

    def test_managed_api_token_can_override_and_disable_legacy_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8")
            legacy = "legacy-api-token-" + "x" * 32
            managed = "managed-api-token-" + "y" * 32
            environment = {
                "VG_STATE_DIR": str(state),
                "VG_DATA_ROOTS": str(state),
                "VG_API_TOKEN": legacy,
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                self.assertEqual(Settings.load(instances).api_token, legacy)
                write_managed_token(
                    state, "api-token", "VG_API_TOKEN", managed)
                self.assertEqual(Settings.load(instances).api_token, managed)
                disable_managed_token(state, "api-token")
                self.assertEqual(Settings.load(instances).api_token, "")

    def test_first_boot_generates_local_replication_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir()
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "VG_STATE_DIR": str(state),
            }, clear=True):
                first = Settings.load(instances)
                second = Settings.load(instances)
                self.assertTrue(first.replication_token.startswith("vg_replication_"))
                self.assertEqual(first.replication_token, second.replication_token)
                self.assertEqual(first.floating_api_token, "")
                write_managed_token(
                    state,
                    "floating-api-token",
                    "VG_FLOATING_API_TOKEN",
                    "fip_" + "x" * 48,
                )
                configured = Settings.load(instances)
            self.assertEqual(configured.floating_api_token, "fip_" + "x" * 48)
            self.assertTrue((state / "secrets" / "replication-token").is_file())

    def test_empty_instances_file_is_valid_for_first_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instances.json"
            path.write_text(json.dumps({"format": 1, "instances": []}), encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "VG_FLOATING_API_TOKEN": "keepalived-test-token-" + "x" * 32,
            }, clear=False):
                settings = Settings.load(path)
            self.assertEqual(settings.instances, ())
            self.assertEqual(settings.node, "local")
            self.assertEqual(
                settings.floating_api_token,
                "keepalived-test-token-" + "x" * 32,
            )

    def test_instances_are_persisted_atomically_and_reloaded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            data_dir = root / "vaultwarden-1"
            data_dir.mkdir(parents=True)
            path = Path(directory) / "state" / "instances.json"
            item = Instance.from_dict({
                "id": "vaultwarden-1",
                "display_name": "Vaultwarden 1",
                "container": "vaultwarden-1",
                "data_dir": str(data_dir),
                "health_port": 80,
                "health_path": "/api/health",
                "floating_service": "vaultwarden-1",
                "include_sends": False,
                "replication_enabled": True,
            })
            with mock.patch.dict(os.environ, {"VG_DATA_ROOTS": str(root)}, clear=False):
                write_instances(path, [item])
                settings = Settings.load(path)
            self.assertEqual(len(settings.instances), 1)
            self.assertEqual(settings.instances[0].data_dir, data_dir.resolve())
            self.assertEqual(settings.instances[0].display_name, "Vaultwarden 1")
            self.assertFalse(settings.instances[0].include_sends)
            self.assertTrue(settings.instances[0].replication_enabled)
            self.assertEqual(list(path.parent.glob("*.new")), [])

    def test_legacy_instance_replication_is_disabled_by_default(self):
        item = Instance.from_dict({
            "id": "legacy",
            "container": "vaultwarden-1",
            "data_dir": "/instances/legacy",
            "health_port": 80,
            "health_path": "/api/health",
        })
        self.assertFalse(item.replication_enabled)
        self.assertEqual(item.display_name, "legacy")
        self.assertEqual(item.data_backend, "auto")

    def test_data_backend_is_explicit_and_validated(self):
        item = Instance.from_dict({
            "id": "managed",
            "container": "vaultwarden-1",
            "data_dir": "/instances/managed",
            "health_port": 80,
            "health_path": "/alive",
            "data_backend": "docker",
        })
        self.assertEqual("docker", item.data_backend)
        self.assertEqual("docker", item.to_dict()["data_backend"])

        raw = item.to_dict()
        raw["data_backend"] = "ssh"
        with self.assertRaisesRegex(ConfigError, "data_backend"):
            Instance.from_dict(raw)


    def test_display_name_rejects_control_characters(self):
        with self.assertRaises(ConfigError):
            Instance.from_dict({
                "id": "vaultwarden-1",
                "display_name": "Vaultwarden\n1",
                "container": "vaultwarden-1",
                "data_dir": "/instances/vaultwarden-1",
                "health_port": 80,
                "health_path": "/api/health",
            })
    def test_backup_retention_is_configurable_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            root.mkdir()
            path = Path(directory) / "instances.json"
            path.write_text(json.dumps({"format": 1, "instances": []}), encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "VG_DATA_ROOTS": str(root),
                "VG_BACKUP_RETENTION": "7",
            }, clear=False):
                settings = Settings.load(path)
            self.assertEqual(settings.backup_retention, 7)
            with mock.patch.dict(os.environ, {
                "VG_DATA_ROOTS": str(root),
                "VG_BACKUP_RETENTION": "0",
            }, clear=False):
                with self.assertRaises(ConfigError):
                    Settings.load(path)

    def test_history_retention_is_configurable_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "instances"
            state = root / "state"
            data.mkdir()
            state.mkdir()
            path = state / "instances.json"
            path.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8"
            )
            environment = {
                "VG_DATA_ROOTS": str(data),
                "VG_STATE_DIR": str(state),
                "VG_HISTORY_MAX_MB": "32",
                "VG_HISTORY_MAX_ENTRIES": "8000",
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                settings = Settings.load(path)
            self.assertEqual(settings.history_max_bytes, 32 * 1024 * 1024)
            self.assertEqual(settings.history_max_entries, 8000)

            for variable, invalid in (
                ("VG_HISTORY_MAX_MB", "0"),
                ("VG_HISTORY_MAX_MB", "257"),
                ("VG_HISTORY_MAX_ENTRIES", "499"),
                ("VG_HISTORY_MAX_ENTRIES", "100001"),
                ("VG_HISTORY_MAX_ENTRIES", "not-a-number"),
            ):
                with self.subTest(variable=variable, invalid=invalid), mock.patch.dict(
                    os.environ,
                    {**environment, variable: invalid},
                    clear=True,
                ), self.assertRaises(ConfigError):
                    Settings.load(path)

    def test_legacy_settings_inherit_replica_root_from_the_template(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            state = Path(directory) / "state"
            root.mkdir()
            state.mkdir()
            path = state / "instances.json"
            path.write_text(
                json.dumps({"format": 1, "instances": []}),
                encoding="utf-8",
            )
            (state / "settings.json").write_text(json.dumps({
                "format": 1,
                "node": "node-1",
                "node_ip": "192.0.2.10",
                "peers": {},
                "floating_api": "http://192.0.2.10:6060",
                "mode": "active",
                "interval_seconds": 30,
                "backup_retention": 5,
                "max_package_mb": 256,
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "VG_DATA_ROOTS": str(root),
                "VG_STATE_DIR": str(state),
                "VG_VAULTWARDEN_ROOT": "/srv/vaultwarden-replicas",
                "VG_ALLOW_INSECURE_HTTP": "true",
            }, clear=False):
                settings = Settings.load(path)

            self.assertEqual(
                "/srv/vaultwarden-replicas",
                settings.vaultwarden_root,
            )

    def test_instance_outside_mounted_roots_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            root.mkdir()
            path = Path(directory) / "instances.json"
            path.write_text(json.dumps({
                "format": 1,
                "instances": [{
                    "id": "outside",
                    "container": "vaultwarden-1",
                    "data_dir": str(Path(directory) / "other"),
                    "health_port": 80,
                    "health_path": "/api/health",
                }]
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, {"VG_DATA_ROOTS": str(root)}, clear=False):
                with self.assertRaises(ConfigError):
                    Settings.load(path)

    def test_secret_files_are_regular_bounded_and_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            data = root / "instances"
            state.mkdir()
            data.mkdir()
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8"
            )
            secrets = {}
            for variable in (
                "VG_API_TOKEN",
                "VG_REPLICATION_TOKEN",
                "VG_FLOATING_API_TOKEN",
            ):
                secret = root / variable.lower()
                secret.write_text(variable.lower() + "_" + "x" * 40 + "\n", encoding="utf-8")
                secrets[f"{variable}_FILE"] = str(secret)
            environment = {
                "VG_STATE_DIR": str(state),
                "VG_DATA_ROOTS": str(data),
                "VG_DOCKER_SOCKET": "/var/run/docker.sock",
                **secrets,
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                settings = Settings.load(instances)
            self.assertTrue(settings.api_token.startswith("vg_api_token_"))
            self.assertTrue(settings.replication_token.startswith("vg_replication_token_"))
            self.assertTrue(settings.floating_api_token.startswith("vg_floating_api_token_"))
            self.assertEqual(settings.docker_socket, "/var/run/docker.sock")

            with mock.patch.dict(os.environ, {
                **environment,
                "VG_API_TOKEN": "another-value",
            }, clear=True), self.assertRaisesRegex(ConfigError, "no ambos"):
                Settings.load(instances)

            link = root / "secret-link"
            try:
                link.symlink_to(Path(secrets["VG_API_TOKEN_FILE"]))
            except OSError:
                return
            with mock.patch.dict(os.environ, {
                **environment,
                "VG_API_TOKEN_FILE": str(link),
            }, clear=True), self.assertRaisesRegex(ConfigError, "regular"):
                Settings.load(instances)

    def test_boolean_paths_and_health_contracts_are_strict(self):
        raw = {
            "id": "strict",
            "container": "vaultwarden-strict",
            "data_dir": "/instances/strict",
            "health_port": 80,
            "health_path": "/alive",
        }
        for key, value in (
            ("include_sends", "false"),
            ("replication_enabled", 1),
            ("health_path", "//other.example/alive"),
            ("health_path", "/alive#fragment"),
            ("data_dir", "instances/relative"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                Instance.from_dict({**raw, key: value})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instances = root / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8"
            )
            with mock.patch.dict(os.environ, {
                "VG_STATE_DIR": str(root),
                "VG_DATA_ROOTS": str(root),
                "VG_ALLOW_INSECURE_HTTP": "sometimes",
            }, clear=True), self.assertRaisesRegex(ConfigError, "true o false"):
                Settings.load(instances)

    def test_nonempty_tokens_are_long_distinct_and_header_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instances = root / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8"
            )
            base = {
                "VG_STATE_DIR": str(root),
                "VG_DATA_ROOTS": str(root),
            }
            for name, value in (
                ("VG_API_TOKEN", "short"),
                ("VG_REPLICATION_TOKEN", "x" * 31),
                ("VG_FLOATING_API_TOKEN", "x" * 32 + "\nheader"),
                ("VG_API_TOKEN", "x" * 32 + "é"),
            ):
                with self.subTest(name=name), mock.patch.dict(
                    os.environ, {**base, name: value}, clear=True
                ), self.assertRaisesRegex(ConfigError, name):
                    Settings.load(instances)

            duplicate = "shared-secret-" + "x" * 32
            write_managed_token(
                root, "replication-token", "VG_REPLICATION_TOKEN", duplicate)
            with mock.patch.dict(os.environ, {
                **base,
                "VG_API_TOKEN": duplicate,
                "VG_REPLICATION_TOKEN": duplicate,
            }, clear=True), self.assertRaisesRegex(ConfigError, "deben ser distintos"):
                Settings.load(instances)

            with mock.patch.dict(os.environ, {
                **base,
                "VG_REPLICATION_TOKEN": duplicate,
                "VG_FLOATING_API_TOKEN": duplicate,
            }, clear=True), self.assertRaisesRegex(ConfigError, "deben ser distintos"):
                Settings.load(instances)

    def test_docker_socket_must_be_an_absolute_local_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instances = root / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}), encoding="utf-8"
            )
            base = {
                "VG_STATE_DIR": str(root),
                "VG_DATA_ROOTS": str(root),
            }
            for endpoint in (
                "var/run/docker.sock",
                "http://docker-control:2375",
                "socket\nname",
            ):
                with self.subTest(endpoint=endpoint), mock.patch.dict(
                    os.environ, {**base, "VG_DOCKER_SOCKET": endpoint}, clear=True
                ), self.assertRaises(ConfigError):
                    Settings.load(instances)


if __name__ == "__main__":
    unittest.main()

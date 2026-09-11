import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import runtime_config
from config import ConfigError, Settings
from replication import ReplicationManager


def settings_payload(mode="observe"):
    return {
        "node": "node-1",
        "node_ip": "192.0.2.10",
        "peers": {"node-2": "https://node-2.example:6062"},
        "floating_api": "https://floating.example:6060",
        "mode": mode,
        "interval_seconds": 30,
        "backup_retention": 5,
        "max_package_mb": 256,
    }


class RuntimeConfigTests(unittest.TestCase):
    def test_package_limit_is_bounded_by_the_snapshot_workspace(self):
        payload = settings_payload()
        payload["max_package_mb"] = 257
        with self.assertRaises(runtime_config.RuntimeConfigError):
            runtime_config.normalize(payload)

    def test_persisted_settings_override_environment_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            data = root / "instances"
            state.mkdir()
            data.mkdir()
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}),
                encoding="utf-8",
            )
            runtime_config.write(state / "settings.json", settings_payload())
            with mock.patch.dict(os.environ, {
                "VG_STATE_DIR": str(state),
                "VG_DATA_ROOTS": str(data),
                "VG_NODE": "environment-node",
            }, clear=False):
                loaded = Settings.load(instances)
            self.assertEqual(loaded.node, "node-1")
            self.assertEqual(
                loaded.peers["node-2"], "https://node-2.example:6062"
            )
            self.assertTrue(loaded.identity_configured)

    def test_active_mode_requires_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            data = root / "instances"
            state.mkdir()
            data.mkdir()
            instances = state / "instances.json"
            instances.write_text(
                json.dumps({"format": 1, "instances": []}),
                encoding="utf-8",
            )
            environment = {
                "VG_STATE_DIR": str(state),
                "VG_DATA_ROOTS": str(data),
                "VG_NODE": "node-1",
                "VG_NODE_IP": "192.0.2.10",
                "VG_ALLOW_INSECURE_HTTP": "true",
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                manager = ReplicationManager(Settings.load(instances), docker=object())
                with self.assertRaises(ConfigError):
                    manager.update_settings({"mode": "active"})
                result = manager.update_settings({
                    "mode": "active",
                    "confirm_active": True,
                })
            self.assertEqual(result["modo"], "active")
            self.assertTrue((state / "settings.json").is_file())

    def test_own_node_cannot_be_a_peer(self):
        payload = settings_payload()
        payload["peers"] = {"node-1": "https://node-1.example:6062"}
        with self.assertRaises(runtime_config.RuntimeConfigError):
            runtime_config.normalize(payload)

    def test_vaultwarden_root_is_per_node_and_cannot_be_server_root(self):
        payload = settings_payload()
        payload["vaultwarden_root"] = "/mnt/user/appdata/"
        normalized = runtime_config.normalize(payload)
        self.assertEqual(
            "/mnt/user/appdata", normalized["vaultwarden_root"])

        for value in ("/", "/tmp/..", "relative"):
            with self.subTest(value=value):
                payload["vaultwarden_root"] = value
                with self.assertRaises(runtime_config.RuntimeConfigError):
                    runtime_config.normalize(payload)

    def test_hosts_and_base_urls_reject_ambiguous_components(self):
        payload = settings_payload()
        for node_ip in (
            "http://192.0.2.10",
            "user@192.0.2.10",
            "192.0.2.10/path",
            "host name",
        ):
            with self.subTest(node_ip=node_ip):
                payload["node_ip"] = node_ip
                with self.assertRaises(runtime_config.RuntimeConfigError):
                    runtime_config.normalize(payload)
        payload = settings_payload()
        for url in (
            "file:///tmp/socket",
            "http://user:secret@node.example:6062",
            "https://node.example:6062?redirect=other",
            "https://node.example:6062#fragment",
        ):
            with self.subTest(url=url):
                payload["floating_api"] = url
                with self.assertRaises(runtime_config.RuntimeConfigError):
                    runtime_config.normalize(payload)

    def test_plain_http_requires_explicit_opt_in_when_configured(self):
        payload = settings_payload()
        payload["floating_api"] = "http://192.0.2.10:6060"
        payload["peers"] = {"node-2": "http://192.0.2.11:6062"}
        with self.assertRaisesRegex(
            runtime_config.RuntimeConfigError, "VG_ALLOW_INSECURE_HTTP"
        ):
            runtime_config.normalize(payload)
        normalized = runtime_config.normalize(
            payload, allow_insecure_http=True
        )
        self.assertEqual("http://192.0.2.10:6060", normalized["floating_api"])
        self.assertTrue(normalized["allow_insecure_http"])

    def test_http_choice_is_persisted_with_the_operational_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            payload = settings_payload()
            payload["floating_api"] = "http://192.0.2.10:6060"
            payload["peers"] = {"node-2": "http://192.0.2.11:6062"}
            payload["allow_insecure_http"] = True
            runtime_config.write(path, payload)

            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(persisted["allow_insecure_http"])
            self.assertTrue(runtime_config.read(path)["allow_insecure_http"])


if __name__ == "__main__":
    unittest.main()

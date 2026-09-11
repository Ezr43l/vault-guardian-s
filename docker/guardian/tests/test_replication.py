import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from config import ConfigError, Instance
from replication import ReplicationError, ReplicationManager
import replication
import snapshot


class ReplicationTests(unittest.TestCase):
    def test_discovery_skips_unreadable_unrelated_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            valid = root / "vaultwarden"
            blocked = root / "unrelated-database"
            valid.mkdir(parents=True)
            blocked.mkdir()
            (valid / "db.sqlite3").write_bytes(b"sqlite")

            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(data_roots=(root,))
            original_is_file = Path.is_file

            def guarded_is_file(path):
                if path == blocked / "db.sqlite3":
                    raise PermissionError("directorio protegido")
                return original_is_file(path)

            with mock.patch.object(Path, "is_file", autospec=True,
                                   side_effect=guarded_is_file):
                result = manager.discovery()

        self.assertEqual([{
            "path": str(valid),
            "nombre": "vaultwarden",
            "tiene_sqlite": True,
        }], result["directorios"])

    def test_persisted_package_reader_rejects_symlinks_and_oversize_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular.vgb"
            regular.write_bytes(b"valid")
            self.assertEqual(b"valid", replication._read_package_file(regular, 5))

            oversized = root / "oversized.vgb"
            oversized.write_bytes(b"123456")
            with self.assertRaisesRegex(ReplicationError, "supera|seguro"):
                replication._read_package_file(oversized, 5)

            linked = root / "linked.vgb"
            linked.symlink_to(regular)
            with self.assertRaisesRegex(ReplicationError, "regular seguro"):
                replication._read_package_file(linked, 5)

    def test_docker_client_uses_local_socket_in_eager_and_lazy_paths(self):
        settings = SimpleNamespace(
            docker_socket="/var/run/docker.sock",
            state_dir=Path("/state"),
            node="node-1",
        )
        supplied = object()
        with mock.patch("replication.data_access.ContainerData"), mock.patch(
            "replication.provisioning_local.LocalProvisioner"
        ), mock.patch("replication.StateStore"), mock.patch(
            "replication.docker_api.DockerClient", return_value=supplied
        ) as docker_client:
            manager = ReplicationManager(settings)
        self.assertIs(manager.docker, supplied)
        docker_client.assert_called_once_with(
            settings.docker_socket,
            allow_local_socket=True,
        )

        lazy = ReplicationManager.__new__(ReplicationManager)
        lazy.settings = settings
        with mock.patch("replication.data_access.ContainerData") as container_data, mock.patch(
            "replication.docker_api.DockerClient", return_value=supplied
        ) as docker_client:
            lazy._data_access()
        docker_client.assert_called_once_with(
            settings.docker_socket,
            allow_local_socket=True,
        )
        container_data.assert_called_once_with(supplied)

    def test_vaultwarden_health_probe_does_not_enable_plain_http_for_peers(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            node_ip="192.0.2.10",
            allow_insecure_http=False,
            ca_file=None,
        )
        instance = Instance.from_dict({
            "id": "vaultwarden-1",
            "container": "vaultwarden-1",
            "data_dir": "/instances/vaultwarden-1",
            "health_port": 8080,
            "health_path": "/alive",
        })
        with mock.patch(
            "replication.http_client.request",
            return_value=mock.Mock(status=200),
        ) as request:
            manager._source_health(instance)
        self.assertTrue(request.call_args.kwargs["allow_http"])

    def test_instance_validation_keeps_health_probe_working_with_tls_default(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "vaultwarden-1"
            data_dir.mkdir()
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                node_ip="192.0.2.10",
                allow_insecure_http=False,
                ca_file=None,
            )
            manager._candidate_is_usable = mock.Mock()
            manager._data_access = mock.Mock(return_value=SimpleNamespace(
                backend=mock.Mock(return_value="docker")
            ))
            manager.docker = SimpleNamespace(inspect=mock.Mock(return_value={
                "existe": True,
                "en_marcha": True,
            }))
            manager.floating_state = mock.Mock(return_value=SimpleNamespace(
                known=True,
                as_dict=lambda: {"known": True},
            ))
            with mock.patch(
                "replication.http_client.request",
                return_value=mock.Mock(status=200),
            ) as request:
                result = manager.validate_instance({
                    "id": "vaultwarden-1",
                    "container": "vaultwarden-1",
                    "data_dir": str(data_dir),
                    "health_port": 8080,
                    "health_path": "/alive",
                })
        self.assertTrue(result["salud"]["ok"])
        self.assertTrue(request.call_args.kwargs["allow_http"])

    @staticmethod
    def manager_for_setup(directory, peers=None, replication_token="",
                          floating_api_token="floating-api-token"):
        manager = ReplicationManager.__new__(ReplicationManager)
        data_root = Path(directory) / "instances"
        data_root.mkdir()
        manager.settings = SimpleNamespace(
            api_token="admin-secret-for-tests-with-32-chars",
            identity_configured=True,
            data_roots=(data_root,),
            peers=peers or {},
            instances=(object(),),
            replication_token=replication_token,
            floating_api_token=floating_api_token,
            mode="observe",
            state_dir=Path(directory),
        )
        manager.docker = object()
        manager._data = SimpleNamespace(mount_available=lambda: True)
        (Path(directory) / "auth.json").write_text(
            json.dumps({"format": 1, "revision": 1,
                        "users": [{"username": "admin"}]}),
            encoding="utf-8",
        )
        return manager

    def test_one_node_is_ready_without_pretending_it_has_redundancy(self):
        with tempfile.TemporaryDirectory() as directory:
            status = self.manager_for_setup(
                directory,
                replication_token="local-encryption-password",
            ).setup_status()

        self.assertEqual("ready", status["state"])
        self.assertTrue(status["ready_for_active"])
        self.assertEqual("single_node", status["redundancy"])
        self.assertFalse(status["checks"]["peers"])
        self.assertFalse(status["requirements"]["peers"])
        self.assertTrue(status["requirements"]["replication_token"])

    def test_cluster_requires_the_shared_password(self):
        with tempfile.TemporaryDirectory() as directory:
            status = self.manager_for_setup(
                directory,
                peers={"node-2": "http://192.0.2.11:6062"},
            ).setup_status()

        self.assertEqual("in_progress", status["state"])
        self.assertFalse(status["ready_for_active"])
        self.assertTrue(status["requirements"]["replication_token"])

    def test_cluster_is_operational_without_a_global_provisioning_root(self):
        with tempfile.TemporaryDirectory() as directory:
            status = self.manager_for_setup(
                directory,
                peers={"node-2": "http://192.0.2.11:6062"},
                replication_token=(
                    "shared-provisioning-password-with-at-least-32-characters"
                ),
            ).setup_status()

        self.assertEqual("ready", status["state"])
        self.assertTrue(status["ready_for_active"])
        self.assertFalse(status["checks"]["provisioning_root"])
        self.assertFalse(status["requirements"]["provisioning_root"])

    def test_content_fingerprint_ignores_package_encryption_timestamp(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        first = {
            "instance": "vaultwarden-1",
            "include_sends": True,
            "created_at": "2026-08-25T09:00:00Z",
            "entries": [{"path": "data/db.sqlite3", "size": 10, "sha256": "abc"}],
        }
        second = dict(first, created_at="2026-08-25T10:00:00Z")
        self.assertEqual(manager._content_fingerprint(first),
                         manager._content_fingerprint(second))

    def test_content_fingerprint_is_independent_of_manifest_entry_order(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        entries = [
            {"path": "data/config.json", "size": 2, "sha256": "b" * 64},
            {"path": "data/db.sqlite3", "size": 10, "sha256": "a" * 64},
        ]
        first = {
            "instance": "vaultwarden-1",
            "include_sends": True,
            "entries": entries,
        }
        second = {**first, "entries": list(reversed(entries))}
        self.assertEqual(
            manager._content_fingerprint(first),
            manager._content_fingerprint(second),
        )

    def test_backup_retention_keeps_newest_files(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(state_dir=Path(directory), backup_retention=2)
            instance = Instance("vaultwarden-1", "vaultwarden-1", Path("/instances/vaultwarden-1"),
                                5743, "/api/version", "vaultwarden")
            manager.settings.instances = (instance,)
            backup_dir = manager._backup_directory(instance)
            for index in range(3):
                path = backup_dir / f"antes-20260825-00000{index}.vgb"
                path.write_bytes(f"backup-{index}".encode())
                os.utime(path, (index + 1, index + 1))
            self.assertEqual(manager._prune_backups(instance), 2)
            result = manager.backups(instance.id)
            self.assertEqual(result["retencion"], 2)
            self.assertEqual([item["nombre"] for item in result["items"]], [
                "antes-20260825-000002.vgb",
                "antes-20260825-000001.vgb",
            ])

    def test_prune_preserves_selected_restore_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(state_dir=Path(directory), backup_retention=1)
            instance = Instance("vaultwarden-1", "vaultwarden-1", Path("/instances/vaultwarden-1"),
                                5743, "/api/version", "vaultwarden")
            manager.settings.instances = (instance,)
            backup_dir = manager._backup_directory(instance)
            selected = backup_dir / "antes-20260825-010000.vgb"
            newest = backup_dir / "antes-20260825-020000.vgb"
            selected.write_bytes(b"selected")
            newest.write_bytes(b"newest")
            os.utime(selected, (1, 1))
            os.utime(newest, (2, 2))
            self.assertEqual(manager._prune_backups(instance, {selected.name}), 2)
            self.assertTrue(selected.exists())
            self.assertTrue(newest.exists())

    def test_partial_apply_restores_the_safety_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "antes-20260830-000000.vgb"
            backup.write_bytes(b"known-good-backup")
            instance = Instance(
                "vaultwarden-1",
                "vaultwarden-1",
                root / "data",
                5743,
                "/api/version",
                "vaultwarden-1",
            )
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                replication_token="replication-token-long-enough-for-tests",
                max_package_bytes=16 * 1024 * 1024,
            )
            access = mock.Mock()
            access.apply_snapshot.side_effect = [
                OSError("disk full after first replace"),
                {"ok": True},
            ]
            manager._data_access = mock.Mock(return_value=access)

            with self.assertRaisesRegex(
                ReplicationError, "restauró automáticamente"
            ):
                manager._apply_with_safety_backup(
                    instance, b"incoming", backup)
            self.assertEqual(2, access.apply_snapshot.call_count)
            self.assertEqual(
                b"incoming", access.apply_snapshot.call_args_list[0].args[1])
            self.assertEqual(
                b"known-good-backup",
                access.apply_snapshot.call_args_list[1].args[1],
            )

    def test_partial_apply_reports_a_failed_automatic_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "antes-20260830-000000.vgb"
            backup.write_bytes(b"known-good-backup")
            instance = Instance(
                "vaultwarden-1",
                "vaultwarden-1",
                root / "data",
                5743,
                "/api/version",
                "vaultwarden-1",
            )
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                replication_token="replication-token-long-enough-for-tests",
                max_package_bytes=16 * 1024 * 1024,
            )
            access = mock.Mock()
            access.apply_snapshot.side_effect = [
                snapshot.SnapshotError("primary failure"),
                OSError("rollback failure"),
            ]
            manager._data_access = mock.Mock(return_value=access)

            with self.assertRaisesRegex(
                ReplicationError, "también el rollback automático"
            ) as context:
                manager._apply_with_safety_backup(
                    instance, b"incoming", backup)
            self.assertIn("primary failure", str(context.exception))
            self.assertIn("rollback failure", str(context.exception))

    def test_applied_fingerprint_survives_manager_state(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(state_dir=Path(directory))
            instance = Instance("vaultwarden-1", "vaultwarden-1", Path("/instances/vaultwarden-1"),
                                5743, "/api/version", "vaultwarden")
            manager._remember_applied(instance, "fingerprint-1", "nodo-1")
            self.assertEqual(manager._read_applied_fingerprint(instance), "fingerprint-1")

    def test_lineage_allows_a_descendant(self):
        self.assertIsNone(ReplicationManager._lineage_conflict(
            {"fingerprint": "current"},
            "current",
            "incoming",
            ["current", "older"],
        ))

    def test_lineage_rejects_a_stale_or_divergent_replica(self):
        reason = ReplicationManager._lineage_conflict(
            {"fingerprint": "current"},
            "current",
            "stale",
            ["older"],
        )
        self.assertIn("no desciende", reason)

    def test_lineage_rejects_unregistered_local_changes(self):
        reason = ReplicationManager._lineage_conflict(
            {"fingerprint": "recorded"},
            "locally-modified",
            "incoming",
            ["locally-modified"],
        )

        self.assertIn("fuera del linaje", reason)

    def test_receive_replaces_divergent_passive_from_confirmed_porter(self):
        token = "replication-token-long-enough-for-authority-test"

        def database(path, value):
            connection = sqlite3.connect(path)
            connection.execute("create table values_table (value text)")
            connection.execute("insert into values_table values (?)", (value,))
            connection.commit()
            connection.close()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_data = root / "source"
            destination_data = root / "destination"
            source_data.mkdir()
            destination_data.mkdir()
            database(source_data / "db.sqlite3", "current-porter")
            database(destination_data / "db.sqlite3", "divergent-passive")
            source = Instance(
                "vaultwarden-1", "vaultwarden-1", source_data,
                5743, "/api/version", "vaultwarden-1",
                replication_enabled=True, data_backend="direct",
            )
            destination = Instance(
                "vaultwarden-1", "vaultwarden-1", destination_data,
                5743, "/api/version", "vaultwarden-1",
                replication_enabled=True, data_backend="direct",
            )
            package = root / "incoming.vgb"
            incoming = snapshot.create_snapshot(
                source, "node-2", token, package, 10 * 1024 * 1024,
            )
            payload = package.read_bytes()

            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                mode="active",
                replication_token=token,
                max_package_bytes=10 * 1024 * 1024,
                node="node-1",
                state_dir=root / "state",
                backup_retention=5,
                instances=(destination,),
                history_max_bytes=16 * 1024 * 1024,
                history_max_entries=5_000,
            )
            manager._lock = threading.RLock()
            manager._last = {}
            manager.docker = mock.Mock()
            manager.docker.inspect.return_value = {
                "existe": True,
                "en_marcha": True,
            }
            manager._data = mock.Mock()
            manager._data.create_snapshot.side_effect = (
                lambda instance, node, secret, output, limit:
                snapshot.create_snapshot(instance, node, secret, output, limit)
            )
            manager._data.apply_snapshot.side_effect = (
                lambda instance, raw, secret, limit:
                snapshot.apply_snapshot(instance, raw, secret, limit)
            )
            manager.floating_state = mock.Mock(return_value=SimpleNamespace(
                known=True,
                portador="node-2",
            ))
            manager._state_store().remember_content(
                destination.id,
                "recorded-before-local-change",
                "node-2",
                "applied",
            )

            result = manager.receive(destination.id, payload, "node-2")

            restored = sqlite3.connect(destination_data / "db.sqlite3")
            self.assertEqual(
                "current-porter",
                restored.execute(
                    "select value from values_table"
                ).fetchone()[0],
            )
            restored.close()
            self.assertEqual("aplicado", result["estado"])
            self.assertEqual(
                "divergencia_reemplazada",
                result["reconciliacion"]["estado"],
            )
            self.assertEqual("node-2", result["reconciliacion"]["autoridad"])
            self.assertTrue(Path(result["backup"]).is_file())
            self.assertEqual(
                manager._content_fingerprint(incoming["manifest"]),
                manager._state_store().content(destination.id)["fingerprint"],
            )
            manager.docker.stop.assert_called_once_with(destination.container)
            manager.docker.start.assert_called_once_with(destination.container)

    def test_baseline_requires_the_same_explicit_fingerprint_before_persisting(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = ReplicationManager.__new__(ReplicationManager)
            instance = Instance(
                "vaultwarden-1",
                "vaultwarden-1",
                Path(directory) / "data",
                5743,
                "/api/version",
                "vaultwarden-1",
            )
            instance.data_dir.mkdir()
            manager.settings = SimpleNamespace(
                instances=(instance,),
                replication_token="test-token-that-is-long-enough",
                max_package_bytes=1024,
                node="node-1",
                state_dir=Path(directory),
            )
            manager._last = {}
            manager._lock = __import__("threading").RLock()
            manifest = {
                "instance": "vaultwarden-1",
                "include_sends": True,
                "entries": [{
                    "path": "data/db.sqlite3",
                    "size": 10,
                    "sha256": "abc",
                }],
            }
            expected = manager._content_fingerprint(manifest)
            manager._data = mock.Mock()
            manager._data.create_snapshot.return_value = {"manifest": manifest}
            with mock.patch(
                "replication.snapshot.create_snapshot",
                return_value={"manifest": manifest},
            ):
                preview = manager.baseline("vaultwarden-1", None, False)
                self.assertFalse(preview["persistido"])
                with self.assertRaises(ReplicationError):
                    manager.baseline("vaultwarden-1", "0" * 64, True)
                confirmed = manager.baseline(
                    "vaultwarden-1", expected, True
                )
            self.assertTrue(confirmed["persistido"])
            self.assertEqual(
                manager._state_store().content("vaultwarden-1")["fingerprint"],
                expected,
            )

    def test_old_local_backup_restores_but_remains_expired_for_live_receive(self):
        token = "replication-token-long-enough-for-retained-backup-tests"

        def database(path, value):
            connection = sqlite3.connect(path)
            connection.execute("create table values_table (value text)")
            connection.execute("insert into values_table values (?)", (value,))
            connection.commit()
            connection.close()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_data = root / "source"
            destination_data = root / "destination"
            source_data.mkdir()
            destination_data.mkdir()
            database(source_data / "db.sqlite3", "retained-backup")
            database(destination_data / "db.sqlite3", "current-destination")
            source = Instance(
                "vaultwarden-1",
                "vaultwarden-1",
                source_data,
                5743,
                "/api/version",
                "vaultwarden-1",
                replication_enabled=True,
                data_backend="direct",
            )
            destination = Instance(
                "vaultwarden-1",
                "vaultwarden-1",
                destination_data,
                5743,
                "/api/version",
                "vaultwarden-1",
                replication_enabled=True,
                data_backend="direct",
            )
            current = root / "current.vgb"
            snapshot.create_snapshot(
                source, "node-2", token, current, 10 * 1024 * 1024
            )
            raw = snapshot._fernet(token).decrypt(current.read_bytes())
            old = snapshot._fernet(token).encrypt_at_time(
                raw, int(time.time()) - 901
            )
            state_dir = root / "state"
            backup_dir = state_dir / "backups" / destination.id
            backup_dir.mkdir(parents=True)
            backup_name = "antes-20260830-000000.vgb"
            (backup_dir / backup_name).write_bytes(old)

            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                mode="active",
                replication_token=token,
                max_package_bytes=10 * 1024 * 1024,
                node="node-1",
                state_dir=state_dir,
                backup_retention=5,
                instances=(destination,),
            )
            manager._lock = threading.RLock()
            manager._last = {}
            manager.docker = mock.Mock()
            manager.docker.inspect.return_value = {
                "existe": True,
                "en_marcha": True,
            }
            manager._data = mock.Mock()
            manager._data.create_snapshot.side_effect = (
                lambda instance, node, secret, output, limit:
                snapshot.create_snapshot(instance, node, secret, output, limit)
            )
            manager._data.apply_snapshot.side_effect = (
                lambda instance, payload, secret, limit:
                snapshot.apply_snapshot(instance, payload, secret, limit)
            )
            manager.floating_state = mock.Mock(return_value=SimpleNamespace(
                known=True,
                portador="node-2",
            ))

            result = manager.restore(destination.id, backup_name, True)

            self.assertEqual("restaurado", result["estado"])
            restored = sqlite3.connect(destination_data / "db.sqlite3")
            self.assertEqual(
                "retained-backup",
                restored.execute(
                    "select value from values_table"
                ).fetchone()[0],
            )
            restored.close()
            manager.docker.stop.assert_called_once_with(destination.container)
            manager.docker.start.assert_called_once_with(destination.container)
            with self.assertRaisesRegex(ReplicationError, "caducado"):
                manager.receive(destination.id, old, "node-2")

    def test_mutating_replication_operations_are_serialized(self):
        cases = (
            ("restore", ("vaultwarden-1", "antes-20260830-000000.vgb", True)),
            ("baseline", ("vaultwarden-1", None, False)),
            ("sync", ("vaultwarden-1",)),
            ("receive", ("vaultwarden-1", b"package", "node-2")),
            ("update_settings", ({},)),
            ("internal_settings", ({},)),
            ("internal_policy", ({},)),
            ("update_cluster_policy", ({},)),
            ("configure_cluster", ({},)),
            ("reconcile_cluster", ({},)),
            ("internal_reconcile_instance", ({},)),
            ("provision_vaultwarden", ({}, "provision:12345678")),
            ("upsert_instance", ({}, None)),
            ("delete_instance", ("vaultwarden-1",)),
            ("internal_instance_config", ({},)),
            ("upsert_instance_cluster", ({}, None)),
            ("delete_instance_cluster", ("vaultwarden-1",)),
        )
        for public_name, arguments in cases:
            with self.subTest(operation=public_name):
                manager = ReplicationManager.__new__(ReplicationManager)
                manager._lock = threading.RLock()
                first_entered = threading.Event()
                release_first = threading.Event()
                second_started = threading.Event()
                second_entered = threading.Event()
                state_lock = threading.Lock()
                call_count = 0
                results = []
                errors = []

                def implementation(*_args, **_kwargs):
                    nonlocal call_count
                    with state_lock:
                        call_count += 1
                        ordinal = call_count
                    if ordinal == 1:
                        first_entered.set()
                        if not release_first.wait(2):
                            raise AssertionError("the first operation was not released")
                    else:
                        second_entered.set()
                    return ordinal

                setattr(manager, f"_{public_name}", implementation)

                def invoke(started=None):
                    if started is not None:
                        started.set()
                    try:
                        results.append(getattr(manager, public_name)(*arguments))
                    except BaseException as exc:  # noqa: BLE001 - propagate thread failures
                        errors.append(exc)

                first = threading.Thread(target=invoke, daemon=True)
                second = threading.Thread(
                    target=invoke, args=(second_started,), daemon=True)
                first.start()
                self.assertTrue(first_entered.wait(1))
                second.start()
                self.assertTrue(second_started.wait(1))
                try:
                    self.assertFalse(
                        second_entered.wait(0.2),
                        f"{public_name} overlapped another mutating operation",
                    )
                finally:
                    release_first.set()
                first.join(2)
                second.join(2)
                self.assertFalse(first.is_alive())
                self.assertFalse(second.is_alive())
                self.assertEqual([], errors)
                self.assertTrue(second_entered.is_set())
                self.assertCountEqual([1, 2], results)

    def test_different_instances_do_not_deadlock_outbound_and_inbound_replication(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager._lock = threading.RLock()
        outbound_entered = threading.Event()
        inbound_entered = threading.Event()
        release = threading.Event()
        errors = []

        def outbound(*_args, **_kwargs):
            outbound_entered.set()
            if not release.wait(2):
                raise AssertionError("outbound replication was not released")
            return "outbound"

        def inbound(*_args, **_kwargs):
            inbound_entered.set()
            return "inbound"

        manager._sync = outbound
        manager._receive = inbound

        def invoke(callable_):
            try:
                callable_()
            except BaseException as exc:  # noqa: BLE001 - propagate thread failures
                errors.append(exc)

        sending = threading.Thread(
            target=invoke,
            args=(lambda: manager.sync("vaultwarden"),),
            daemon=True,
        )
        receiving = threading.Thread(
            target=invoke,
            args=(lambda: manager.receive("vaultcircuit", b"package", "node-2"),),
            daemon=True,
        )
        sending.start()
        self.assertTrue(outbound_entered.wait(1))
        receiving.start()
        try:
            self.assertTrue(
                inbound_entered.wait(1),
                "a different instance was blocked behind outbound replication",
            )
        finally:
            release.set()
        sending.join(2)
        receiving.join(2)
        self.assertEqual([], errors)
        self.assertFalse(sending.is_alive())
        self.assertFalse(receiving.is_alive())

    def test_replication_send_retries_a_temporarily_busy_peer(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            replication_token="replication-token-long-enough",
            node="node-1",
            allow_insecure_http=True,
            ca_file=None,
        )
        instance = Instance(
            "vaultwarden-1", "vaultwarden-1", Path("/instances/vaultwarden-1"),
            5743, "/api/version", "vaultwarden-1",
        )
        with mock.patch(
            "replication.http_client.request",
            side_effect=[
                replication.http_client.HttpStatusError(503),
                SimpleNamespace(body=b'{"estado":"sin_cambios"}'),
            ],
        ) as request, mock.patch("replication.time.sleep") as sleep:
            result = manager._send(
                "node-2", "http://192.0.2.20:6062", instance, b"package"
            )

        self.assertTrue(result["ok"])
        self.assertEqual("sin_cambios", result["respuesta"]["estado"])
        self.assertEqual(2, request.call_count)
        sleep.assert_called_once_with(1)

    def test_concurrent_instance_writes_are_serialized_without_lost_updates(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager._lock = threading.RLock()
        instances_file = Path("/state/instances.json")
        manager.settings = SimpleNamespace(
            instances=(), instances_file=instances_file
        )
        manager._candidate_is_usable = mock.Mock()
        manager.config = lambda: {
            "ids": [item.id for item in manager.settings.instances]
        }
        persisted = []
        write_calls = []
        first_write = threading.Event()
        second_write = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()
        errors = []

        def fake_write(_path, items):
            write_calls.append([item.id for item in items])
            if len(write_calls) == 1:
                first_write.set()
                if not release_first.wait(2):
                    raise AssertionError("first write was not released")
            else:
                second_write.set()
            persisted[:] = items

        def fake_load(_path):
            return SimpleNamespace(
                instances=tuple(persisted), instances_file=instances_file
            )

        def raw(identifier):
            return {
                "id": identifier,
                "container": identifier,
                "data_dir": f"/instances/{identifier}",
                "health_port": 8000 if identifier.endswith("1") else 8001,
                "health_path": "/alive",
                "floating_service": identifier,
            }

        def invoke(payload, started=None):
            if started is not None:
                started.set()
            try:
                manager.upsert_instance(payload)
            except BaseException as exc:  # noqa: BLE001 - propagate thread failures
                errors.append(exc)

        with mock.patch("replication.write_instances", side_effect=fake_write), mock.patch(
            "replication.Settings.load", side_effect=fake_load
        ):
            first = threading.Thread(target=invoke, args=(raw("vaultwarden-1"),))
            second = threading.Thread(
                target=invoke,
                args=(raw("vaultwarden-2"), second_started),
            )
            first.start()
            self.assertTrue(first_write.wait(1))
            second.start()
            self.assertTrue(second_started.wait(1))
            try:
                self.assertFalse(second_write.wait(0.2))
                self.assertEqual(1, len(write_calls))
            finally:
                release_first.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(
            [["vaultwarden-1"], ["vaultwarden-1", "vaultwarden-2"]],
            write_calls,
        )
        self.assertEqual(
            ["vaultwarden-1", "vaultwarden-2"],
            [item.id for item in manager.settings.instances],
        )

    def test_configuration_mutation_can_reenter_the_shared_lock(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager._lock = threading.RLock()
        manager._update_settings = mock.Mock(return_value={"ok": True})
        manager._internal_policy = lambda raw: manager.update_settings(raw)
        results = []
        thread = threading.Thread(
            target=lambda: results.append(manager.internal_policy({"mode": "observe"}))
        )
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive(), "the nested mutation deadlocked")
        self.assertEqual([{"ok": True}], results)

    def test_serialized_operation_can_reenter_lock_via_remember(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager._lock = threading.RLock()
        manager._last = {}
        store = mock.Mock()
        store.remember_result.return_value = {"at": "2026-08-30T00:00:00Z"}
        manager._state_store = mock.Mock(return_value=store)
        manager._sync = lambda identifier, context=None: manager._remember(
            identifier, {"estado": "sin_cambios"}
        )
        results = []
        errors = []

        def invoke():
            try:
                results.append(manager.sync("vaultwarden-1"))
            except BaseException as exc:  # noqa: BLE001 - propagate thread failures
                errors.append(exc)

        worker = threading.Thread(target=invoke, daemon=True)
        worker.start()
        worker.join(2)

        self.assertFalse(worker.is_alive(), "nested RLock acquisition deadlocked")
        self.assertEqual([], errors)
        self.assertEqual([{"estado": "sin_cambios"}], results)
        self.assertIn("vaultwarden-1", manager._last)

    def test_selected_sync_is_forwarded_only_to_the_vip_porter(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        instance = Instance(
            "vaultwarden-1",
            "vaultwarden-1",
            Path("/instances/vaultwarden-1"),
            5743,
            "/api/version",
            "vaultwarden-1",
        )
        manager.settings = SimpleNamespace(
            node="node-1",
            peers={"node-2": "http://192.0.2.11:6062"},
            replication_token="replication-secret",
        )
        manager.instance = mock.Mock(return_value=instance)
        manager.floating_state = mock.Mock(return_value=SimpleNamespace(
            known=True,
            portador="node-2",
        ))
        manager._send_peer_json = mock.Mock(return_value={
            "estado": "sincronizado",
            "destinos_ok": 1,
            "destinos_esperados": 1,
        })
        manager._remember = mock.Mock(side_effect=lambda identifier, result: result)

        result = manager.sync_selected("vaultwarden-1")

        manager._send_peer_json.assert_called_once_with(
            "node-2",
            "http://192.0.2.11:6062",
            "/api/v1/internal/sync/vaultwarden-1",
            {"solicitado_desde": "node-1"},
            method="POST",
            timeout=120,
        )
        self.assertEqual(result["instance"], "vaultwarden-1")
        self.assertEqual(result["ejecutado_por"], "node-2")

    def test_selected_sync_on_local_porter_records_only_once(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        instance = Instance(
            "vaultwarden-1",
            "vaultwarden-1",
            Path("/instances/vaultwarden-1"),
            5743,
            "/api/version",
            "vaultwarden-1",
            replication_enabled=True,
        )
        manager.settings = SimpleNamespace(node="node-1", peers={})
        manager.instance = mock.Mock(return_value=instance)
        manager.floating_state = mock.Mock(return_value=SimpleNamespace(
            known=True,
            portador="node-1",
        ))
        manager.sync = mock.Mock(return_value={"estado": "sin_cambios"})
        manager._remember = mock.Mock()

        result = manager.sync_selected("vaultwarden-1")

        context = {
            "instance": "vaultwarden-1",
            "ejecutado_por": "node-1",
            "solicitado_desde": "node-1",
        }
        manager.sync.assert_called_once_with("vaultwarden-1", context=context)
        manager._remember.assert_not_called()
        self.assertEqual(result["estado"], "sin_cambios")

    def test_cluster_policy_is_validated_then_applied_to_every_peer(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            node="node-1",
            peers={
                "node-2": "http://192.0.2.11:6062",
                "node-3": "http://192.0.2.12:6062",
            },
            replication_token="replication-secret",
        )
        policy = {
            "mode": "active",
            "interval_seconds": 60,
            "backup_retention": 5,
            "max_package_mb": 256,
        }
        manager._validate_policy = mock.Mock(return_value=(policy, True))
        manager._send_peer_json = mock.Mock(return_value={"estado": "ok"})
        manager.update_settings = mock.Mock(return_value={"modo": "active"})

        result = manager.update_cluster_policy({**policy, "confirm_active": True})

        self.assertEqual(manager._send_peer_json.call_count, 4)
        manager.update_settings.assert_called_once_with({
            **policy,
            "confirm_active": True,
        })
        self.assertEqual(result["nodos"], 3)

    def test_cluster_configuration_is_distributed_from_one_panel(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            replication_token="replication-secret",
            allow_insecure_http=True,
        )
        policy = {
            "mode": "observe",
            "interval_seconds": 30,
            "backup_retention": 5,
            "max_package_mb": 256,
        }
        manager._validate_policy = mock.Mock(return_value=(policy, False))
        manager._validate_full_settings = mock.Mock()
        manager._send_peer_json = mock.Mock(return_value={"estado": "ok"})
        manager.internal_settings = mock.Mock(return_value={
            "estado": "aplicado",
            "nodo": "node-1",
        })
        manager.reconcile_cluster = mock.Mock(return_value={
            "estado": "sin_cambios",
            "trabajos": [],
            "replicas_creadas": 0,
            "cluster_state": "unconfigured",
        })

        result = manager.configure_cluster({
            "local_name": "node-1",
            "members": [
                {
                    "name": "node-1",
                    "guardian_url": "http://192.0.2.10:6062",
                    "node_ip": "192.0.2.10",
                    "floating_api": "http://192.0.2.10:8080",
                },
                {
                    "name": "node-2",
                    "guardian_url": "http://192.0.2.11:6062",
                    "node_ip": "192.0.2.11",
                    "floating_api": "http://192.0.2.11:8080",
                },
            ],
            "policy": policy,
        })

        self.assertEqual(result["nodos"], 2)
        self.assertEqual(manager._send_peer_json.call_count, 2)
        validate_call, apply_call = manager._send_peer_json.call_args_list
        self.assertFalse(validate_call.args[3]["apply"])
        self.assertTrue(apply_call.args[3]["apply"])
        remote_settings = apply_call.args[3]["settings"]
        self.assertEqual(remote_settings["node"], "node-2")
        self.assertEqual(remote_settings["peers"], {
            "node-1": "http://192.0.2.10:6062",
        })
        local_settings = manager.internal_settings.call_args.args[0]["settings"]
        self.assertEqual(local_settings["node"], "node-1")
        self.assertEqual(local_settings["peers"], {
            "node-2": "http://192.0.2.11:6062",
        })
        manager.reconcile_cluster.assert_called_once_with({"confirm": True})
        self.assertEqual(
            result["reconciliacion"]["estado"], "sin_cambios")

    def test_cluster_configuration_rejects_http_without_opt_in(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            replication_token="replication-secret",
            allow_insecure_http=False,
        )
        with self.assertRaisesRegex(ConfigError, "VG_ALLOW_INSECURE_HTTP"):
            manager.configure_cluster({
                "local_name": "node-1",
                "members": [{
                    "name": "node-1",
                    "guardian_url": "http://192.0.2.10:6062",
                    "node_ip": "192.0.2.10",
                    "floating_api": "http://192.0.2.10:8080",
                }],
                "policy": {},
            })

    def test_reconciliation_asks_the_porter_to_seed_only_the_missing_node(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            node="node-1",
            mode="active",
            peers={
                "node-2": "http://192.0.2.11:6062",
                "node-3": "http://192.0.2.12:6062",
            },
            replication_token="replication-secret",
        )
        missing = {
            "state": "degraded",
            "nodes": [
                {
                    "name": "node-1",
                    "reachable": True,
                    "status": {"instancias": [{"id": "vaultwarden-1"}]},
                },
                {
                    "name": "node-2",
                    "reachable": True,
                    "status": {"instancias": [{"id": "vaultwarden-1"}]},
                },
                {
                    "name": "node-3",
                    "reachable": True,
                    "status": {"instancias": []},
                },
            ],
            "instances": [{
                "id": "vaultwarden-1",
                "porter": "node-2",
                "fingerprints": {
                    "node-1": "same",
                    "node-2": "same",
                },
            }],
        }
        protected = {
            **missing,
            "state": "protected",
            "nodes": [
                *missing["nodes"][:2],
                {
                    "name": "node-3",
                    "reachable": True,
                    "status": {"instancias": [{"id": "vaultwarden-1"}]},
                },
            ],
        }
        manager.cluster_status = mock.Mock(side_effect=[missing, protected])

        def send(peer, base_url, path, payload, **kwargs):
            if path == "/api/v1/internal/reconciliation":
                return {
                    "stage": "complete",
                    "complete": True,
                    "target_node": payload["target"],
                }
            return {"estado": "sincronizado", "destinos_ok": 2}

        manager._send_peer_json = mock.Mock(side_effect=send)

        result = manager.reconcile_cluster({"confirm": True})

        calls = manager._send_peer_json.call_args_list
        self.assertEqual(2, len(calls))
        self.assertEqual("node-2", calls[0].args[0])
        self.assertEqual(
            "/api/v1/internal/reconciliation", calls[0].args[2])
        self.assertEqual("node-3", calls[0].args[3]["target"])
        self.assertTrue(
            calls[0].args[3]["transaction"].startswith("backfill-"))
        self.assertEqual(
            "/api/v1/internal/sync/vaultwarden-1", calls[1].args[2])
        self.assertEqual(1, result["replicas_creadas"])
        self.assertEqual("reconciliado", result["estado"])

    def test_reconciliation_waits_without_mutating_in_observe_mode(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            node="node-1",
            mode="observe",
            peers={"node-2": "http://192.0.2.11:6062"},
            replication_token="replication-secret",
        )
        manager._reconciliation_plan = mock.Mock(return_value=(
            {"state": "degraded"},
            [{
                "instance": "vaultwarden-1",
                "porter": "node-1",
                "target": "node-2",
                "transaction": "backfill-12345678",
            }],
        ))
        manager._send_peer_json = mock.Mock()

        result = manager.reconcile_cluster({"confirm": True})

        self.assertEqual("pendiente_modo_activo", result["estado"])
        manager._send_peer_json.assert_not_called()

    def test_instance_configuration_is_applied_to_the_whole_group(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            node="node-1",
            peers={
                "node-2": "http://192.0.2.11:6062",
                "node-3": "http://192.0.2.12:6062",
            },
            replication_token="replication-secret",
        )
        manager._send_peer_json = mock.Mock(return_value={"estado": "ok"})
        manager.internal_instance_config = mock.Mock(return_value={
            "estado": "aplicado",
            "nodo": "node-1",
            "instance": "vaultwarden-1",
        })
        payload = {
            "action": "upsert",
            "instance": {"id": "vaultwarden-1"},
            "existing_id": None,
        }

        result = manager._cluster_instance_change(payload)

        self.assertEqual(manager._send_peer_json.call_count, 4)
        manager.internal_instance_config.assert_called_once_with({
            **payload,
            "apply": True,
        })
        self.assertEqual(result["nodos"], 3)

    def test_passive_automatic_cycle_waits_without_recording_a_false_failure(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager._lock = threading.RLock()
        instance = Instance(
            "vaultwarden-1",
            "vaultwarden-1",
            Path("/instances/vaultwarden-1"),
            5743,
            "/api/version",
            "vaultwarden-1",
            replication_enabled=True,
        )
        manager.settings = SimpleNamespace(
            node="node-1",
            mode="active",
            replication_token="replication-secret",
        )
        manager.instance = mock.Mock(return_value=instance)
        manager.floating_state = mock.Mock(return_value=SimpleNamespace(
            portador="node-2",
            is_node_active=lambda node: False,
        ))
        manager._remember = mock.Mock()

        result = manager.sync("vaultwarden-1")

        self.assertEqual(result, {
            "estado": "en_espera",
            "motivo": "este Guardian espera al portador de la IP",
            "portador": "node-2",
        })
        manager._remember.assert_not_called()

    def test_provisioning_requires_active_protection_before_docker(self):
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.settings = SimpleNamespace(
            mode="observe",
            replication_token="local-encryption-password",
        )

        with self.assertRaisesRegex(
            ReplicationError,
            "activa primero la protección del grupo",
        ):
            manager.provision_vaultwarden(
                {
                    "source_container": "vaultwarden-source",
                    "instance_id": "vaultwarden-1",
                    "confirm": True,
                },
                "provision:test-123",
            )

    def test_provisioning_claims_the_vip_only_after_every_replica_is_ready(self):
        class SourceDocker:
            def inspect_full(self, name):
                if name != "vaultwarden-source":
                    return None
                return {
                    "Name": "/vaultwarden-source",
                    "Path": "/start.sh",
                    "Args": [],
                    "Image": "sha256:" + "a" * 64,
                    "Config": {
                        "Image": "vaultwarden/server:latest",
                        "Env": [
                            "ADMIN_TOKEN=source-secret-value",
                            "SIGNUPS_ALLOWED=false",
                        ],
                    },
                    "HostConfig": {
                        "Privileged": False,
                        "NetworkMode": "bridge",
                        "CapAdd": None,
                        "Devices": [],
                        "PortBindings": {
                            "80/tcp": [{
                                "HostIp": "",
                                "HostPort": "8080",
                            }],
                        },
                    },
                    "Mounts": [{
                        "Type": "bind",
                        "Source": "/mnt/user/appdata/vaultwarden-source",
                        "Destination": "/data",
                        "RW": True,
                    }],
                    "State": {"Running": True},
                }

            def inspect_image(self, image):
                return {
                    "RepoDigests": [
                        "vaultwarden/server@sha256:" + "b" * 64,
                    ],
                }

        class SourceData:
            def create_snapshot(
                self, instance, source_node, token, output, max_bytes,
                parent_fingerprint=None, ancestor_fingerprints=None,
            ):
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"same-encrypted-package")
                return {
                    "manifest": {
                        "format": 1,
                        "instance": instance.id,
                        "source_node": source_node,
                        "created_at": "2026-08-25T12:00:00Z",
                        "include_sends": True,
                        "entries": [{
                            "path": "data/db.sqlite3",
                            "size": 10,
                            "sha256": "abc",
                        }],
                    },
                }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                node="node-1",
                mode="active",
                node_ip="192.0.2.10",
                peers={"node-2": "http://192.0.2.11:6062"},
                instances=(),
                replication_token=(
                    "shared-provisioning-password-with-at-least-32-characters"
                ),
                max_package_bytes=16 * 1024 * 1024,
                state_dir=root / "state",
                data_roots=(root / "instances",),
                floating_api_token="floating-api-token",
                floating_api="http://192.0.2.10:6060",
            )
            manager.docker = SourceDocker()
            manager._data = SourceData()
            manager._state = __import__("state").StateStore(
                manager.settings.state_dir, "node-1")
            manager._lock = threading.RLock()
            manager._source_health = mock.Mock()
            manager.upsert_instance = mock.Mock()
            events = []

            def send_json(peer, base_url, path, payload, **kwargs):
                events.append(path)
                if path.endswith(("preflight", "prepare")):
                    self.assertNotIn(
                        "source-secret-value", json.dumps(payload))
                    private = __import__("sealed").unseal(
                        payload,
                        manager.settings.replication_token,
                        "provisioning-spec",
                    )
                    self.assertEqual(
                        "/mnt/user/appdata/vaultwarden-1",
                        private["target_path"],
                    )
                return {"stage": path.rsplit("/", 1)[-1], "node": peer}

            def send_bytes(peer, base_url, path, payload, **kwargs):
                events.append(path)
                self.assertEqual(b"same-encrypted-package", payload)
                return {"stage": "data_applied", "node": peer}

            manager._send_peer_json = send_json
            manager._send_peer_bytes = send_bytes
            manager.upsert_instance.side_effect = lambda raw: events.append(
                "source_registered")

            def claim(*args, **kwargs):
                events.append("floating_claim")
                return {
                    "ip": "192.0.2.200",
                    "converged": True,
                    "repeated": False,
                }

            request = {
                "source_container": "vaultwarden-source",
                "instance_id": "vaultwarden-1",
                "display_name": "Vaultwarden 1",
                "data_directory": "vaultwarden-1",
                "destination_paths": {
                    "node-2": "/mnt/user/appdata/vaultwarden-1",
                },
                "health_path": "/alive",
                "include_sends": True,
                "confirm": True,
            }
            with mock.patch("replication.floating.claim", side_effect=claim):
                result = manager.provision_vaultwarden(
                    request, "provision:test-123")
                repeated = manager.provision_vaultwarden(
                    request, "provision:test-123")

            self.assertTrue(result["complete"])
            self.assertTrue(repeated["complete"])
            self.assertEqual("floating_claim", events[-1])
            self.assertLess(
                events.index("source_registered"),
                events.index("floating_claim"),
            )
            self.assertEqual(1, events.count("floating_claim"))
            state_text = (
                manager.settings.state_dir
                / "provisioning"
                / "provision:test-123.json"
            ).read_text(encoding="utf-8")
            self.assertNotIn("source-secret-value", state_text)

    def test_porter_backfill_reuses_provisioning_without_claiming_another_ip(self):
        class SourceDocker:
            def inspect_full(self, name):
                if name != "vaultwarden-source":
                    return None
                return {
                    "Name": "/vaultwarden-source",
                    "Path": "/start.sh",
                    "Args": [],
                    "Image": "sha256:" + "a" * 64,
                    "Config": {
                        "Image": "vaultwarden/server:latest",
                        "Env": [
                            "ADMIN_TOKEN=source-secret-value",
                            "SIGNUPS_ALLOWED=false",
                        ],
                    },
                    "HostConfig": {
                        "Privileged": False,
                        "NetworkMode": "bridge",
                        "CapAdd": None,
                        "Devices": [],
                        "PortBindings": {
                            "80/tcp": [{
                                "HostIp": "",
                                "HostPort": "8080",
                            }],
                        },
                    },
                    "Mounts": [{
                        "Type": "bind",
                        "Source": "/mnt/user/appdata/vaultwarden-source",
                        "Destination": "/data",
                        "RW": True,
                    }],
                    "State": {"Running": True},
                }

            def inspect_image(self, image):
                return {
                    "RepoDigests": [
                        "vaultwarden/server@sha256:" + "b" * 64,
                    ],
                }

        class SourceData:
            def create_snapshot(
                self, instance, source_node, token, output, max_bytes,
                parent_fingerprint=None, ancestor_fingerprints=None,
            ):
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"reconciliation-package")
                return {
                    "manifest": {
                        "format": 1,
                        "instance": instance.id,
                        "source_node": source_node,
                        "created_at": "2026-08-25T15:00:00Z",
                        "include_sends": True,
                        "entries": [{
                            "path": "data/db.sqlite3",
                            "size": 10,
                            "sha256": "abc",
                        }],
                    },
                }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = Instance(
                "vaultwarden-1",
                "vaultwarden-source",
                root / "instances" / "vaultwarden-1",
                8080,
                "/alive",
                "vaultwarden-1",
                replication_enabled=True,
                display_name="Vaultwarden 1",
            )
            manager = ReplicationManager.__new__(ReplicationManager)
            manager.settings = SimpleNamespace(
                node="node-1",
                node_ip="192.0.2.10",
                peers={"node-3": "http://192.0.2.12:6062"},
                instances=(instance,),
                replication_token=(
                    "shared-provisioning-password-with-at-least-32-characters"
                ),
                max_package_bytes=16 * 1024 * 1024,
                state_dir=root / "state",
            )
            manager.docker = SourceDocker()
            manager._data = SourceData()
            manager._state = __import__("state").StateStore(
                manager.settings.state_dir, "node-1")
            manager._lock = threading.RLock()
            manager._source_health = mock.Mock()
            manager.floating_state = mock.Mock(return_value=SimpleNamespace(
                known=True,
                portador="node-1",
                local_healthy=True,
            ))
            events = []

            def send_json(peer, base_url, path, payload, **kwargs):
                events.append(path)
                if path.endswith(("preflight", "prepare")):
                    self.assertNotIn(
                        "source-secret-value", json.dumps(payload))
                return {"stage": path.rsplit("/", 1)[-1], "node": peer}

            def send_bytes(peer, base_url, path, payload, **kwargs):
                events.append(path)
                self.assertEqual(b"reconciliation-package", payload)
                return {"stage": "data_applied", "node": peer}

            manager._send_peer_json = send_json
            manager._send_peer_bytes = send_bytes
            request = {
                "instance_id": "vaultwarden-1",
                "target": "node-3",
                "transaction": "backfill-" + "c" * 40,
            }
            with mock.patch("replication.floating.claim") as claim:
                result = manager.internal_reconcile_instance(request)
                event_count = len(events)
                repeated = manager.internal_reconcile_instance(request)

            self.assertTrue(result["complete"])
            self.assertTrue(repeated["complete"])
            self.assertEqual(event_count, len(events))
            claim.assert_not_called()
            self.assertEqual([
                "/api/v1/internal/provisioning/preflight",
                "/api/v1/internal/provisioning/prepare",
                "/api/v1/internal/provisioning/" + request["transaction"] + "/snapshot",
                "/api/v1/internal/provisioning/" + request["transaction"] + "/activate",
            ], events)
            state_text = (
                manager.settings.state_dir
                / "provisioning"
                / (request["transaction"] + ".json")
            ).read_text(encoding="utf-8")
            self.assertNotIn("source-secret-value", state_text)


if __name__ == "__main__":
    unittest.main()

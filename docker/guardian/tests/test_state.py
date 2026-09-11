import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import state as state_module
from state import StateError, StateStore


class StateStoreTests(unittest.TestCase):
    def test_results_content_and_history_survive_a_new_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root, "node-1")
            event = store.remember_result("vaultwarden-1", {"estado": "sincronizado"})
            store.remember_content(
                "vaultwarden-1", "new", "node-1", "source",
                parent_fingerprint="old",
                confirmed_fingerprint="new",
                ancestor_fingerprints=["old", "older", "old"],
            )

            reloaded = StateStore(root, "node-1")
            self.assertEqual(reloaded.last_result("vaultwarden-1"), event)
            self.assertEqual(reloaded.history(10), [event])
            content = reloaded.content("vaultwarden-1")
            self.assertEqual(content["fingerprint"], "new")
            self.assertEqual(content["ancestor_fingerprints"], ["old", "older"])
            self.assertEqual(list(root.rglob("*.new")), [])

    def test_history_limit_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory), "node-1")
            for index in range(4):
                store.remember_result("vaultwarden-1", {"index": index})
            self.assertEqual(
                [item["result"]["index"] for item in store.history(2)],
                [3, 2],
            )

    def test_history_rotates_by_bytes_and_entries_preserving_recent_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(
                root,
                "node-1",
                history_max_bytes=2048,
                history_max_entries=5,
            )
            for index in range(20):
                store.remember_result(
                    "vaultwarden-1",
                    {"index": index, "detail": "x" * 180},
                )

            recent = store.history(20)
            indexes = [item["result"]["index"] for item in recent]
            self.assertGreaterEqual(len(indexes), 2)
            self.assertLessEqual(len(indexes), 5)
            self.assertEqual(indexes, list(range(19, 19 - len(indexes), -1)))
            self.assertLessEqual(store.history_path.stat().st_size, 2048)
            self.assertEqual(stat.S_IMODE(store.history_path.stat().st_mode), 0o600)
            self.assertEqual([], list(root.glob(".history.jsonl.*.new")))

    def test_concurrent_rotation_produces_only_complete_unique_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(
                root,
                "node-1",
                history_max_bytes=64 * 1024,
                history_max_entries=20,
            )
            barrier = threading.Barrier(4)
            failures = []

            def writer(worker: int) -> None:
                try:
                    barrier.wait(timeout=5)
                    for index in range(15):
                        store.remember_result(
                            f"vaultwarden-{worker}",
                            {"value": f"{worker}:{index}"},
                        )
                except Exception as exc:  # noqa: BLE001 - se reenvía al hilo principal
                    failures.append(exc)

            threads = [threading.Thread(target=writer, args=(worker,)) for worker in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15)

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            recent = store.history(100)
            self.assertEqual(len(recent), 20)
            values = [item["result"]["value"] for item in recent]
            self.assertEqual(len(values), len(set(values)))
            physical = store.history_path.read_bytes().splitlines()
            self.assertEqual(len(physical), 20)
            self.assertTrue(all(isinstance(json.loads(line), dict) for line in physical))
            self.assertEqual([], list(root.glob(".history.jsonl.*.new")))

    def test_large_legacy_history_is_read_from_the_tail_and_compacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = root / "history.jsonl"
            valid = [
                json.dumps({"result": {"index": index}}).encode() + b"\n"
                for index in range(20)
            ]
            history.write_bytes(b"x" * (3 * 1024 * 1024) + b"\n" + b"".join(valid))
            store = StateStore(
                root,
                "node-1",
                history_max_bytes=1024 * 1024,
                history_max_entries=500,
            )
            original_read = os.read
            bytes_read = 0

            def counted_read(descriptor: int, amount: int) -> bytes:
                nonlocal bytes_read
                payload = original_read(descriptor, amount)
                bytes_read += len(payload)
                return payload

            with mock.patch.object(state_module.os, "read", side_effect=counted_read):
                recent = store.history(3)
            self.assertEqual(
                [item["result"]["index"] for item in recent],
                [19, 18, 17],
            )
            self.assertLess(bytes_read, 256 * 1024)

            bytes_read = 0
            with mock.patch.object(state_module.os, "read", side_effect=counted_read):
                store.remember_result("vaultwarden-1", {"index": 20})
            self.assertLessEqual(bytes_read, 1024 * 1024)
            self.assertLessEqual(history.stat().st_size, 1024 * 1024)
            self.assertEqual(store.history(1)[0]["result"]["index"], 20)

    def test_huge_corrupt_tail_never_causes_an_unbounded_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = root / "history.jsonl"
            history.write_bytes(
                json.dumps({"result": {"index": 0}}).encode()
                + b"\n"
                + b"x" * (3 * 1024 * 1024)
            )
            store = StateStore(
                root,
                "node-1",
                history_max_bytes=1024 * 1024,
                history_max_entries=500,
            )
            original_read = os.read
            bytes_read = 0

            def counted_read(descriptor: int, amount: int) -> bytes:
                nonlocal bytes_read
                payload = original_read(descriptor, amount)
                bytes_read += len(payload)
                return payload

            with mock.patch.object(state_module.os, "read", side_effect=counted_read):
                self.assertEqual(store.history(100), [])
            self.assertLessEqual(bytes_read, 1024 * 1024)

            bytes_read = 0
            with mock.patch.object(state_module.os, "read", side_effect=counted_read):
                store.remember_result("vaultwarden-1", {"index": 1})
            self.assertLessEqual(bytes_read, 1024 * 1024)
            self.assertLessEqual(history.stat().st_size, 1024 * 1024)
            self.assertEqual(store.history(1)[0]["result"]["index"], 1)

    def test_corrupt_tail_is_recovered_without_losing_recent_valid_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root, "node-1", 4096, 10)
            for index in range(3):
                store.remember_result("vaultwarden-1", {"index": index})
            with store.history_path.open("ab") as handle:
                handle.write(b"partial-corrupt-record")

            recovered = StateStore(root, "node-1", 4096, 10)
            self.assertEqual(
                [item["result"]["index"] for item in recovered.history(3)],
                [2, 1, 0],
            )
            recovered.remember_result("vaultwarden-1", {"index": 3})
            self.assertEqual(
                [item["result"]["index"] for item in recovered.history(4)],
                [3, 2, 1, 0],
            )
            self.assertNotIn(b"partial-corrupt-record", store.history_path.read_bytes())

    def test_history_rejects_symlinks_and_rotation_failure_keeps_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("do-not-touch\n", encoding="utf-8")
            link = root / "history.jsonl"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("el sistema no permite crear symlinks")
            store = StateStore(root, "node-1", 2048, 3)
            with self.assertRaises(StateError):
                store.history(1)
            with self.assertRaises(StateError):
                store.remember_result("vaultwarden-1", {"index": 0})
            self.assertEqual(target.read_text(encoding="utf-8"), "do-not-touch\n")
            link.unlink()

            for index in range(3):
                store.remember_result("vaultwarden-1", {"index": index})
            before = store.history_path.read_bytes()
            original_replace = os.replace

            def fail_history_replace(source, destination, *args, **kwargs):
                if str(destination) == "history.jsonl":
                    raise OSError("injected rotation failure")
                return original_replace(source, destination, *args, **kwargs)

            with mock.patch.object(
                state_module.os, "replace", side_effect=fail_history_replace
            ), self.assertRaises(StateError):
                store.remember_result("vaultwarden-1", {"index": 3})
            self.assertEqual(store.history_path.read_bytes(), before)
            self.assertEqual([], list(root.glob(".history.jsonl.*.new")))

    def test_history_rejects_a_fifo_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("la plataforma no permite crear FIFO")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "history.jsonl", 0o600)
            store = StateStore(root, "node-1")
            with self.assertRaises(StateError):
                store.history(1)
            with self.assertRaises(StateError):
                store.remember_result("vaultwarden-1", {"index": 0})

    def test_provisioning_state_is_atomic_and_path_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root, "node-1")
            record = store.remember_provisioning(
                "provision:12345678",
                {"stage": "prepared", "container": "vaultwarden-1"},
            )
            reloaded = StateStore(root, "node-1")
            self.assertEqual(
                record, reloaded.provisioning("provision:12345678"))
            self.assertEqual([], list(root.rglob("*.new")))
            with self.assertRaises(ValueError):
                store.provisioning("../../escape")


if __name__ == "__main__":
    unittest.main()

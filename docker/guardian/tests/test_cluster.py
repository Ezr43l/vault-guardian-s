import json
import unittest
from unittest import mock

import cluster


def node_status(name: str, fingerprint: str) -> dict:
    return {
        "nodo": name,
        "politica": {
            "mode": "active",
            "interval_seconds": 60,
            "backup_retention": 5,
            "max_package_mb": 256,
        },
        "instancias": [{
            "id": "vaultwarden-1",
            "contenido": {"fingerprint": fingerprint},
            "floating_ip": {"conocido": True, "portador": "node-1"},
        }],
    }


class ClusterTests(unittest.TestCase):
    def test_single_configured_node_has_no_redundancy(self):
        result = cluster.collect_cluster(node_status("node-1", "same"), {})
        self.assertEqual(result["state"], "degraded")

    def test_unreachable_expected_node_is_degraded(self):
        peer = {"name": "node-2", "reachable": False, "error": "timeout"}
        with mock.patch.object(cluster, "_read_peer", return_value=peer):
            result = cluster.collect_cluster(
                node_status("node-1", "same"),
                {"node-2": "http://node-2:6062"},
            )
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["reachable_nodes"], 1)

    def test_different_fingerprints_are_a_conflict(self):
        peer = {
            "name": "node-2",
            "reachable": True,
            "status": node_status("node-2", "different"),
        }
        with mock.patch.object(cluster, "_read_peer", return_value=peer):
            result = cluster.collect_cluster(
                node_status("node-1", "current"),
                {"node-2": "http://node-2:6062"},
            )
        self.assertEqual(result["state"], "conflict")
        self.assertEqual(result["instances"][0]["state"], "conflict")

    def test_policy_consistency_compares_every_reachable_node(self):
        matching = {
            "name": "node-2",
            "reachable": True,
            "status": node_status("node-2", "same"),
        }
        with mock.patch.object(cluster, "_read_peer", return_value=matching):
            result = cluster.collect_cluster(
                node_status("node-1", "same"),
                {"node-2": "http://node-2:6062"},
            )
        self.assertTrue(result["policy_consistent"])

        different = node_status("node-2", "same")
        different["politica"]["interval_seconds"] = 120
        matching["status"] = different
        with mock.patch.object(cluster, "_read_peer", return_value=matching):
            result = cluster.collect_cluster(
                node_status("node-1", "same"),
                {"node-2": "http://node-2:6062"},
            )
        self.assertFalse(result["policy_consistent"])

    def test_peer_status_uses_the_replication_credential(self):
        response = cluster.http_client.HttpResponse(
            200, json.dumps(node_status("node-2", "same")).encode("utf-8")
        )
        with mock.patch.object(
            cluster.http_client, "request", return_value=response
        ) as request:
            result = cluster._read_peer(
                "node-2", "http://node-2:6062", "replication-secret", True
            )
        self.assertEqual(
            "replication-secret",
            request.call_args.kwargs["headers"]["X-Replication-Token"],
        )
        self.assertTrue(request.call_args.kwargs["allow_http"])
        self.assertTrue(result["reachable"])


if __name__ == "__main__":
    unittest.main()

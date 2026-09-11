import datetime as dt
import unittest

import readiness


NOW = dt.datetime(2026, 8, 25, 12, 0, tzinfo=dt.timezone.utc)


def item(porter="node-1", health=False, fingerprint="current", updated="2026-08-25T11:59:30Z"):
    return {
        "id": "vaultwarden-1",
        "floating_ip": {
            "conocido": True,
            "portador": porter,
            "salud_local": health,
        },
        "contenido": {
            "fingerprint": fingerprint,
            "confirmed_fingerprint": fingerprint,
            "updated_at": updated,
        },
    }


def cluster(fingerprints, state="protected"):
    return {
        "state": state,
        "instances": [{
            "id": "vaultwarden-1",
            "state": state,
            "fingerprints": fingerprints,
        }],
    }


class ReadinessTests(unittest.TestCase):
    def test_current_healthy_porter_is_ready(self):
        result = readiness.evaluate(
            "node-1",
            item(health=True, fingerprint=None),
            cluster({}, "unknown"),
            True,
            30,
            NOW,
        )
        self.assertTrue(result["ready"])
        self.assertEqual(result["role"], "porter")

    def test_candidate_matching_the_porter_is_ready(self):
        result = readiness.evaluate(
            "node-2",
            item(),
            cluster({"node-1": "current", "node-2": "current"}),
            True,
            30,
            NOW,
        )
        self.assertTrue(result["ready"])

    def test_candidate_behind_current_porter_is_rejected(self):
        result = readiness.evaluate(
            "node-2",
            item(fingerprint="old"),
            cluster({"node-1": "current", "node-2": "old"}, "conflict"),
            True,
            30,
            NOW,
        )
        self.assertFalse(result["ready"])
        self.assertIn("behind_current_porter", result["reasons"])
        self.assertIn("replication_conflict", result["reasons"])

    def test_fresh_confirmed_candidate_can_fail_over_when_porter_is_unreachable(self):
        result = readiness.evaluate(
            "node-2",
            item(),
            cluster({"node-2": "current"}, "degraded"),
            True,
            30,
            NOW,
        )
        self.assertTrue(result["ready"])

    def test_stale_candidate_is_rejected_when_porter_is_unreachable(self):
        result = readiness.evaluate(
            "node-2",
            item(updated="2026-08-25T11:55:00Z"),
            cluster({"node-2": "current"}, "degraded"),
            True,
            30,
            NOW,
        )
        self.assertFalse(result["ready"])
        self.assertIn("replica_too_old_for_failover", result["reasons"])


if __name__ == "__main__":
    unittest.main()

import json
import unittest

import sealed


class SealedTests(unittest.TestCase):
    def test_round_trip_does_not_expose_secret_values(self):
        token = "shared-password-with-more-than-32-characters"
        payload = {
            "transaction": "provision:0001",
            "environment": ["ADMIN_TOKEN=very-secret-value"],
        }
        envelope = sealed.seal(payload, token, "provisioning-spec")

        self.assertNotIn("very-secret-value", json.dumps(envelope))
        self.assertEqual(
            payload,
            sealed.unseal(envelope, token, "provisioning-spec"),
        )

    def test_wrong_password_or_purpose_is_rejected(self):
        token = "shared-password-with-more-than-32-characters"
        envelope = sealed.seal({"value": 1}, token, "provisioning-spec")

        with self.assertRaises(sealed.SealedError):
            sealed.unseal(
                envelope,
                "different-password-with-more-than-32-chars",
                "provisioning-spec",
            )
        with self.assertRaisesRegex(sealed.SealedError, "no corresponde"):
            sealed.unseal(envelope, token, "different-purpose")

    def test_short_password_is_rejected(self):
        with self.assertRaisesRegex(sealed.SealedError, "32"):
            sealed.seal({"value": 1}, "short", "provisioning-spec")

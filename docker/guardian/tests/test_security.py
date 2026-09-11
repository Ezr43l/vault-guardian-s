import json
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

from security import (
    SecurityError,
    SecurityManager,
    _totp,
    hash_password,
    verify_password,
)
import security


PASSWORD = "Correct-Horse-Battery-77"


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.settings = SimpleNamespace(
            state_dir=Path(self.temporary.name),
            replication_token="replication-secret-long-enough",
            session_minutes=30,
            allow_insecure_portal=True,
            peers={},
        )
        self.security = SecurityManager(self.settings)
        self.security.setup_first_user({
            "username": "admin",
            "display_name": "Administrator",
            "password": PASSWORD,
            "password_confirmation": PASSWORD,
        })

    def tearDown(self):
        self.temporary.cleanup()

    def test_password_hash_uses_scrypt_and_never_contains_plaintext(self):
        stored = hash_password(PASSWORD)
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertTrue(verify_password(PASSWORD, stored))
        self.assertFalse(verify_password("incorrect-password", stored))
        self.assertNotIn(PASSWORD, stored)

    def test_password_verification_rejects_untrusted_kdf_parameters_without_work(self):
        stored = hash_password(PASSWORD)
        expensive = stored.replace("scrypt$32768$8$1$", "scrypt$1048576$8$64$")
        with mock.patch.object(
            security.hashlib, "scrypt", side_effect=AssertionError("KDF invoked")
        ) as derive:
            self.assertFalse(verify_password(PASSWORD, expensive))
            self.assertFalse(verify_password("x" * 257, stored))
        derive.assert_not_called()

    def test_setup_creates_one_account_and_a_signed_session(self):
        status = self.security.status()
        self.assertTrue(status["available"])
        self.assertEqual(1, status["user_count"])
        token, identity = self.security.login("admin", PASSWORD, "", "127.0.0.1")
        self.assertEqual("admin", identity.username)
        self.assertEqual(identity, self.security.read_session(token))
        public = self.security.public_session(identity)
        self.assertIn("csrf_token", public)
        self.assertNotIn("password_hash", public)
        persisted = (Path(self.temporary.name) / "auth.json").read_text()
        self.assertNotIn(PASSWORD, persisted)

    def test_public_setup_never_runs_the_kdf_after_initialization(self):
        with mock.patch.object(
            security, "hash_password", side_effect=AssertionError("KDF invoked")
        ) as derive:
            with self.assertRaises(SecurityError) as context:
                self.security.setup_first_user({
                    "username": "attacker",
                    "password": "Attacker-Chosen-Password-884",
                    "password_confirmation": "Attacker-Chosen-Password-884",
                })
        self.assertEqual("AUTH_ALREADY_CONFIGURED", context.exception.code)
        derive.assert_not_called()

    def test_fresh_install_requires_user_supplied_first_account(self):
        fresh_settings = SimpleNamespace(
            state_dir=Path(self.temporary.name) / "fresh",
            replication_token="replication-secret-long-enough",
            session_minutes=30,
            allow_insecure_portal=True,
            peers={},
        )
        fresh = SecurityManager(fresh_settings)
        self.assertTrue(fresh.status()["setup_required"])
        self.assertFalse(fresh.status()["configured"])
        user, replication, session = fresh.setup_first_user({
            "username": "owner",
            "display_name": "Owner",
            "password": "Owner-Chosen-Password-882",
            "password_confirmation": "Owner-Chosen-Password-882",
        })
        self.assertEqual("owner", user["username"])
        self.assertEqual({}, replication["failed"])
        self.assertEqual("owner", session[1].username)
        self.assertFalse(fresh.status()["setup_required"])
        with self.assertRaises(SecurityError) as context:
            fresh.setup_first_user({
                "username": "other",
                "password": "Other-Chosen-Password-883",
                "password_confirmation": "Other-Chosen-Password-883",
            })
        self.assertEqual("AUTH_ALREADY_CONFIGURED", context.exception.code)

    def test_current_identity_is_distributed_when_peers_are_added(self):
        revision = self.security.users()["revision"]
        self.security.refresh_peers({
            "node-2": "http://192.0.2.11:6062",
        })
        expected = {"updated": ["node-2"], "failed": {}}
        with mock.patch.object(
            self.security, "_replicate", return_value=expected
        ) as replicate:
            result = self.security.replicate_current()
        self.assertEqual(expected, result)
        replicated_state = replicate.call_args.args[0]
        self.assertEqual(revision, replicated_state["revision"])
        self.assertEqual(revision, self.security.users()["revision"])
        self.assertEqual("admin", replicated_state["users"][0]["username"])

    def test_identity_replication_uses_the_strict_http_client(self):
        self.security.refresh_peers({"node-2": "https://node-2.example:6062"})
        self.security.ca_file = "/run/secrets/private-ca.pem"
        response = security.http_client.HttpResponse(200, b"{}")
        with mock.patch.object(
            security.http_client, "request", return_value=response
        ) as request:
            result = self.security.replicate_current()
        self.assertEqual(["node-2"], result["updated"])
        self.assertEqual({}, result["failed"])
        self.assertEqual(
            "/api/v1/internal/security", request.call_args.args[1]
        )
        self.assertEqual("PUT", request.call_args.kwargs["method"])
        self.assertFalse(request.call_args.kwargs["allow_http"])
        self.assertEqual(
            "/run/secrets/private-ca.pem", request.call_args.kwargs["ca_file"]
        )

    def test_invalid_credentials_and_weak_new_password_are_rejected(self):
        with self.assertRaisesRegex(SecurityError, "Usuario o contraseña"):
            self.security.login("admin", "incorrect-password", "", "127.0.0.1")
        with self.assertRaises(SecurityError) as context:
            self.security.add_user({
                "username": "operator",
                "display_name": "Operator",
                "password": "short",
            })
        self.assertEqual("WEAK_PASSWORD", context.exception.code)

    def test_invalid_login_names_are_bounded_and_rate_limited(self):
        oversized = "attacker-" + "x" * 70000
        for _ in range(security.ATTEMPT_LIMIT_PER_USER):
            with self.assertRaises(SecurityError) as context:
                self.security.login(
                    oversized, "incorrect-password", "", "198.51.100.10")
            self.assertEqual("INVALID_CREDENTIALS", context.exception.code)
            self.assertEqual(401, context.exception.status)
        with self.assertRaises(SecurityError) as context:
            self.security.login(
                oversized, "incorrect-password", "", "198.51.100.10")
        self.assertEqual("LOGIN_RATE_LIMIT", context.exception.code)
        self.assertLessEqual(len(self.security._attempts), 2)
        self.assertTrue(all(oversized not in key for key in self.security._attempts))

    def test_login_attempt_map_has_a_hard_global_bound(self):
        for index in range(security.ATTEMPT_KEY_LIMIT // 2 + 128):
            keys = self.security._attempt_keys(
                f"198.51.{index // 256}.{index % 256}",
                f"user{index}",
            )
            self.security._record_failure(keys)
        self.assertLessEqual(
            len(self.security._attempts), security.ATTEMPT_KEY_LIMIT)

    def test_user_rate_limit_cannot_be_bypassed_with_multiple_origins(self):
        for index in range(security.ATTEMPT_LIMIT_PER_USER):
            with self.assertRaises(SecurityError) as context:
                self.security.login(
                    "admin",
                    "incorrect-password",
                    "",
                    f"198.51.100.{index + 1}",
                )
            self.assertEqual("INVALID_CREDENTIALS", context.exception.code)

        with self.assertRaises(SecurityError) as context:
            self.security.login(
                "admin", "incorrect-password", "", "203.0.113.200"
            )
        self.assertEqual("LOGIN_RATE_LIMIT", context.exception.code)

    def test_origin_rate_limit_still_blocks_username_spraying(self):
        origin = "198.51.100.200"
        for index in range(security.ATTEMPT_LIMIT_PER_ORIGIN):
            with self.assertRaises(SecurityError) as context:
                self.security.login(
                    f"unknown-user-{index}",
                    "incorrect-password",
                    "",
                    origin,
                )
            self.assertEqual("INVALID_CREDENTIALS", context.exception.code)

        with self.assertRaises(SecurityError) as context:
            self.security.login(
                "one-more-unknown-user", "incorrect-password", "", origin
            )
        self.assertEqual("LOGIN_RATE_LIMIT", context.exception.code)

    def test_users_can_be_added_updated_disabled_and_deleted(self):
        user, replication = self.security.add_user({
            "username": "operator",
            "display_name": "Operator",
            "password": "Operator-Initial-Password-44",
        })
        self.assertEqual("operator", user["username"])
        self.assertEqual([], replication["updated"])
        changed, _ = self.security.update_user("operator", {
            "display_name": "Operations",
            "enabled": False,
        })
        self.assertFalse(changed["enabled"])
        self.security.delete_user("operator")
        self.assertEqual(1, len(self.security.users()["items"]))
        with self.assertRaises(SecurityError) as context:
            self.security.delete_user("admin")
        self.assertEqual("LAST_USER", context.exception.code)

    def test_totp_activation_invalidates_old_sessions_and_encrypts_secret(self):
        old_token, old_identity = self.security.login(
            "admin", PASSWORD, "", "127.0.0.1")
        setup, _ = self.security.setup_totp("admin")
        code = _totp(setup["secret"], int(time.time()) // 30)
        recovery, _, new_session = self.security.confirm_totp("admin", code)
        self.assertEqual(10, len(recovery))
        self.assertIsNone(self.security.read_session(old_token))
        self.assertIsNotNone(self.security.read_session(new_session[0]))
        state = json.loads(
            (Path(self.temporary.name) / "auth.json").read_text())
        serialized = json.dumps(state)
        self.assertNotIn(setup["secret"], serialized)
        self.assertNotIn(recovery[0], serialized)
        with self.assertRaises(SecurityError) as context:
            self.security.login("admin", PASSWORD, "", "127.0.0.2")
        self.assertEqual("TWO_FACTOR_REQUIRED", context.exception.code)
        token, _ = self.security.login(
            "admin", PASSWORD, code, "127.0.0.2")
        self.assertIsNotNone(self.security.read_session(token))

    def test_recovery_code_is_consumed_after_one_login(self):
        setup, _ = self.security.setup_totp("admin")
        code = _totp(setup["secret"], int(time.time()) // 30)
        recovery, _, _ = self.security.confirm_totp("admin", code)
        token, _ = self.security.login(
            "admin", PASSWORD, recovery[0], "127.0.0.3")
        self.assertIsNotNone(self.security.read_session(token))
        with self.assertRaises(SecurityError):
            self.security.login(
                "admin", PASSWORD, recovery[0], "127.0.0.3")
        user = self.security.users()["items"][0]
        self.assertEqual(9, user["recovery_codes_remaining"])

    def test_peer_state_rejects_an_older_revision(self):
        current = json.loads(
            (Path(self.temporary.name) / "auth.json").read_text())
        self.security.add_user({
            "username": "second",
            "display_name": "Second",
            "password": "Second-Account-Password-55",
        })
        with self.assertRaises(SecurityError) as context:
            self.security.apply_from_peer({"phase": "apply", "state": current})
        self.assertEqual("STALE_SECURITY_STATE", context.exception.code)

    def test_peer_state_rejects_malformed_revision_and_kdf_contract(self):
        current = json.loads(
            (Path(self.temporary.name) / "auth.json").read_text()
        )
        malformed_revision = {**current, "revision": {"not": "an integer"}}
        with self.assertRaises(SecurityError) as context:
            self.security.apply_from_peer({
                "phase": "apply", "state": malformed_revision
            })
        self.assertEqual("INVALID_SECURITY_STATE", context.exception.code)

        expensive = json.loads(json.dumps(current))
        expensive["revision"] += 1
        expensive["users"][0]["password_hash"] = expensive["users"][0][
            "password_hash"
        ].replace("scrypt$32768$8$1$", "scrypt$1048576$8$64$")
        with mock.patch.object(
            security.hashlib, "scrypt", side_effect=AssertionError("KDF invoked")
        ) as derive, self.assertRaises(SecurityError) as context:
            self.security.apply_from_peer({"phase": "apply", "state": expensive})
        derive.assert_not_called()
        self.assertEqual("INVALID_SECURITY_STATE", context.exception.code)

        incomplete = json.loads(json.dumps(current))
        incomplete["revision"] += 1
        del incomplete["users"][0]["id"]
        with self.assertRaises(SecurityError) as context:
            self.security.apply_from_peer({"phase": "apply", "state": incomplete})
        self.assertEqual("INVALID_SECURITY_STATE", context.exception.code)


if __name__ == "__main__":
    unittest.main()

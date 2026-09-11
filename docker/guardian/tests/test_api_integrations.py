import json
import tempfile
import unittest
from pathlib import Path

from api_integrations import ApiIntegrationError, ApiIntegrationStore


class ApiIntegrationStoreTests(unittest.TestCase):
    def test_each_application_has_an_independent_manageable_token(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ApiIntegrationStore(directory)
            first, first_token = store.create("Monitorización")
            second_token = "custom-api-token-" + "x" * 32
            second, returned = store.create("RTFM", second_token)

            self.assertEqual(second_token, returned)
            self.assertNotEqual(first_token, second_token)
            self.assertEqual(
                {"Monitorización", "RTFM"},
                {item["name"] for item in store.list()},
            )
            self.assertEqual(first_token, store.reveal(first["id"]))
            self.assertEqual(second_token, store.reveal(second["id"]))

            authenticated = store.authenticate(
                first_token, "/api/v1/status")
            self.assertEqual(first["id"], authenticated["id"])
            observed = next(
                item for item in store.list() if item["id"] == first["id"])
            self.assertEqual(1, observed["usage_count"])
            self.assertEqual("/api/v1/status", observed["last_endpoint"])
            self.assertIsNotNone(observed["last_used_at"])

            updated, replacement = store.update(
                first["id"], name="Prometheus", token="")
            self.assertEqual("Prometheus", updated["name"])
            self.assertNotEqual(first_token, replacement)
            self.assertIsNone(store.authenticate(first_token))
            self.assertIsNotNone(store.authenticate(replacement))

            deleted = store.delete(second["id"])
            self.assertEqual("RTFM", deleted["name"])
            self.assertEqual(1, len(store.list()))

    def test_legacy_token_is_named_without_changing_its_value(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ApiIntegrationStore(directory)
            legacy = "legacy-api-token-" + "y" * 32
            store.import_legacy(legacy)
            store.import_legacy(legacy)

            items = store.list()
            self.assertEqual(1, len(items))
            self.assertEqual("legacy_api_token", items[0]["id"])
            self.assertTrue(items[0]["legacy"])
            self.assertEqual(legacy, store.reveal("legacy_api_token"))

    def test_tokens_are_not_in_the_public_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ApiIntegrationStore(directory)
            item, token = store.create("Aplicación externa")

            serialized = json.dumps(item)
            self.assertNotIn(token, serialized)
            self.assertIn("token_hint", item)

    def test_invalid_or_duplicated_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ApiIntegrationStore(directory)
            token = "duplicate-api-token-" + "z" * 32
            store.create("Primera", token)
            with self.assertRaisesRegex(ApiIntegrationError, "pertenece"):
                store.create("Segunda", token)
            with self.assertRaisesRegex(ApiIntegrationError, "nombre"):
                store.create("x")
            with self.assertRaisesRegex(ApiIntegrationError, "token"):
                store.create("Tercera", "short")

    def test_registry_rejects_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            secrets = state / "secrets"
            secrets.mkdir()
            target = state / "outside.json"
            target.write_text('{"format":1,"applications":[]}', encoding="utf-8")
            (secrets / "api-integrations.json").symlink_to(target)

            with self.assertRaisesRegex(ApiIntegrationError, "regular"):
                ApiIntegrationStore(state).list()


if __name__ == "__main__":
    unittest.main()

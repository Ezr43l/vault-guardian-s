import json
import http.client
import threading
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from server import GuardianServer


class FakeManager:
    def __init__(self, state_dir):
        self.settings = SimpleNamespace(
            api_token="admin-token",
            replication_token="replication-token",
            max_package_bytes=1024 * 1024,
            node="node-1",
            mode="observe",
            instances=(),
            state_dir=Path(state_dir),
            peers={},
            session_minutes=30,
            allow_insecure_portal=True,
        )
        self.api_apps = [{
            "id": "legacy_api_token",
            "name": "Integración anterior sin identificar",
            "token_hint": "admin-tok…oken",
            "created_at": "2026-09-10T12:00:00+00:00",
            "updated_at": "2026-09-10T12:00:00+00:00",
            "last_used_at": None,
            "last_endpoint": None,
            "usage_count": 0,
            "legacy": True,
        }]

    def authenticate_api_integration(self, token, endpoint=""):
        return token == "admin-token"

    def list_api_integrations(self):
        return {"items": list(self.api_apps)}

    def create_api_integration(self, payload):
        item = {
            **self.api_apps[0],
            "id": "app_1234567890abcdef12345678",
            "name": payload["name"],
            "legacy": False,
        }
        self.api_apps.append(item)
        return {"application": item, "token": "generated-" + "x" * 32}

    def update_api_application(self, identifier, payload):
        item = next(value for value in self.api_apps if value["id"] == identifier)
        item["name"] = payload["name"]
        return {"application": item}

    def rotate_api_application(self, identifier, payload):
        item = next(value for value in self.api_apps if value["id"] == identifier)
        return {"application": item, "token": "rotated-" + "y" * 32}

    def reveal_api_application(self, identifier):
        next(value for value in self.api_apps if value["id"] == identifier)
        return {"token": "revealed-" + "z" * 32}

    def delete_api_application(self, identifier):
        self.api_apps = [value for value in self.api_apps if value["id"] != identifier]
        return {"deleted": identifier}

    def status(self):
        return {
            "nodo": "node-1",
            "modo": "observe",
            "configurado": False,
            "instancias": [],
            "pares": [],
        }

    def instance_readiness(self, instance_id):
        return {
            "ready": False,
            "instance": instance_id,
            "node": "node-1",
            "role": "candidate",
            "reasons": ["missing_fingerprint"],
        }

    def backups(self, instance_id):
        return {"instance": instance_id, "items": [], "retencion": 5}

    def sync(self, instance_id, context=None):
        result = {"estado": "sin_cambios", "instance": instance_id}
        result.update(context or {})
        return result

    def sync_selected(self, instance_id):
        return {
            "estado": "sin_cambios",
            "instance": instance_id,
            "ejecutado_por": "node-1",
        }

    def update_cluster_policy(self, payload):
        return {"estado": "aplicado_en_grupo", "nodos": 1, "politica": payload}

    def update_keepalived_integration(self, payload):
        return {
            "configured": bool(payload.get("token")),
            "floating_api": "http://host.docker.internal:6060",
        }

    def update_application_settings(self, payload):
        self.settings.session_minutes = payload["session_minutes"]
        self.settings.allow_insecure_portal = payload["allow_insecure_portal"]
        return payload

    def update_api_integration(self, payload):
        return {"configured": bool(payload.get("token"))}

    def disable_api_integration(self):
        return {"configured": False}

    def update_private_ca(self, payload):
        return {"configured": bool(payload.get("pem"))}

    def disable_private_ca(self):
        return {"configured": False}

    def configure_enrollment_token(self, token):
        self.settings.replication_token = token

    def enrollment_token(self):
        return self.settings.replication_token

    def configure_cluster(self, payload):
        return {"estado": "grupo_configurado", "nodos": len(payload["members"])}

    def internal_policy(self, payload):
        return {"estado": "validado", "nodo": "node-1"}

    def internal_settings(self, payload):
        return {"estado": "validado", "nodo": "node-1"}

    def reconcile_cluster(self, payload):
        return {
            "estado": "reconciliado",
            "replicas_creadas": 1,
            "confirm": payload.get("confirm"),
        }

    def internal_reconcile_instance(self, payload):
        return {
            "stage": "complete",
            "complete": True,
            "instance": payload.get("instance_id"),
            "target_node": payload.get("target"),
        }

    def internal_instance_config(self, payload):
        return {"estado": "validado", "nodo": "node-1", "instance": "vaultwarden-1"}

    def upsert_instance_cluster(self, payload, existing_id=None):
        return {
            "estado": "instancia_aplicada_en_grupo",
            "nodos": 1,
            "instance": existing_id or payload["id"],
        }

    def delete_instance_cluster(self, instance_id):
        return {"estado": "instancia_aplicada_en_grupo", "nodos": 1, "instance": instance_id}

    def internal_provisioning_preflight(self, payload):
        return {"stage": "validated", "transaction": "provision:12345678"}

    def internal_provisioning_prepare(self, payload):
        return {"stage": "prepared", "transaction": "provision:12345678"}

    def internal_provisioning_snapshot(self, transaction, payload):
        return {
            "stage": "data_applied",
            "transaction": transaction,
            "bytes": len(payload),
        }

    def internal_provisioning_activate(self, transaction):
        return {"stage": "registered", "transaction": transaction}

    def provisioning_transaction(self, transaction):
        return {"stage": "registered", "transaction": transaction}

    def provision_vaultwarden(self, payload, transaction):
        return {
            "stage": "complete",
            "complete": True,
            "instance": payload["instance_id"],
            "transaction": transaction,
        }


class ServerRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.static_dir = mock.patch(
            "server.STATIC_DIR",
            Path(__file__).resolve().parents[1] / "web",
        )
        cls.static_dir.start()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.server = GuardianServer(
            ("127.0.0.1", 0),
            FakeManager(cls.temporary.name),
        )
        cls.server.security.setup_first_user({
            "username": "admin",
            "display_name": "Administrator",
            "password": "Correct-Horse-Battery-77",
            "password_confirmation": "Correct-Horse-Battery-77",
        })
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temporary.cleanup()
        cls.static_dir.stop()

    def request(
        self, path, token=None, method="GET", body=None,
        internal_token=None, idempotency=None,
    ):
        encoded = (
            json.dumps(body).encode("utf-8")
            if body is not None
            else None
        )
        request = urllib.request.Request(
            self.base_url + path,
            data=encoded,
            method=method,
        )
        if token:
            request.add_header("Authorization", "Bearer " + token)
        if internal_token:
            request.add_header("X-Replication-Token", internal_token)
        if idempotency:
            request.add_header("Idempotency-Key", idempotency)
        if encoded is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def raw_session_request(self, headers, body):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3)
        connection.putrequest(
            "POST", "/api/v1/session", skip_accept_encoding=True)
        connection.putheader("Content-Type", "application/json")
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        result = (
            response.status,
            response.getheader("Connection"),
            json.loads(response.read()),
        )
        connection.close()
        return result

    def test_root_and_legacy_index_serve_the_guided_panel(self):
        for path in ("/", "/index.html"):
            with urllib.request.urlopen(self.base_url + path, timeout=2) as response:
                page = response.read().decode("utf-8")
            self.assertIn('data-view-panel="inicio"', page)
            self.assertIn('href="/panel.css"', page)

    def test_keepalived_token_is_written_only_by_an_administrator(self):
        payload = {"token": "fip_" + "x" * 48}
        status, _ = self.request(
            "/api/v1/integrations/keepalived", method="PUT", body=payload)
        self.assertEqual(status, 401)
        status, result = self.request(
            "/api/v1/integrations/keepalived",
            token="admin-token",
            method="PUT",
            body=payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["configured"])
        self.assertNotIn("token", result)

    def test_removed_template_settings_are_administered_through_the_portal(self):
        settings = {
            "session_minutes": 60,
            "history_max_mb": 24,
            "history_max_entries": 6000,
            "allow_insecure_portal": True,
        }
        for path, method, body in (
            ("/api/v1/application-settings", "PUT", settings),
            ("/api/v1/integrations/api-token", "PUT", {"token": "x" * 48}),
            ("/api/v1/tls/private-ca", "PUT", {"pem": "certificate"}),
            ("/api/v1/integrations/api-token", "DELETE", None),
            ("/api/v1/tls/private-ca", "DELETE", None),
        ):
            with self.subTest(path=path, method=method):
                unauthorized, _ = self.request(path, method=method, body=body)
                self.assertEqual(unauthorized, 401)
                status, result = self.request(
                    path,
                    token="admin-token",
                    method=method,
                    body=body,
                )
                self.assertEqual(status, 200)
                self.assertIsInstance(result, dict)

    def test_enrollment_token_is_only_returned_to_an_administrator(self):
        status, _ = self.request("/api/v1/cluster/enrollment-token")
        self.assertEqual(status, 401)
        status, result = self.request(
            "/api/v1/cluster/enrollment-token", token="admin-token")
        self.assertEqual(status, 200)
        self.assertEqual(result["token"], "replication-token")

    def test_api_applications_are_managed_only_by_a_portal_session(self):
        status, _ = self.request("/api/v1/integrations/applications")
        self.assertEqual(401, status)
        status, _ = self.request(
            "/api/v1/integrations/applications", token="admin-token")
        self.assertEqual(401, status)

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3)
        login_body = json.dumps({
            "username": "admin",
            "password": "Correct-Horse-Battery-77",
        })
        connection.request(
            "POST", "/api/v1/session", body=login_body,
            headers={"Content-Type": "application/json"})
        login = connection.getresponse()
        self.assertEqual(200, login.status)
        cookie = login.getheader("Set-Cookie").split(";", 1)[0]
        csrf = json.loads(login.read())["session"]["csrf_token"]

        connection.request(
            "GET", "/api/v1/integrations/applications",
            headers={"Cookie": cookie})
        listed = connection.getresponse()
        self.assertEqual(200, listed.status)
        self.assertGreaterEqual(len(json.loads(listed.read())["items"]), 1)

        body = json.dumps({"name": "RTFM"})
        connection.request(
            "POST", "/api/v1/integrations/applications", body=body,
            headers={
                "Cookie": cookie,
                "X-CSRF-Token": csrf,
                "Content-Type": "application/json",
            },
        )
        created = connection.getresponse()
        self.assertEqual(201, created.status)
        item = json.loads(created.read())["application"]

        connection.request(
            "GET",
            "/api/v1/integrations/applications/" + item["id"] + "/token",
            headers={"Cookie": cookie},
        )
        revealed = connection.getresponse()
        self.assertEqual(200, revealed.status)
        self.assertIn("token", json.loads(revealed.read()))

        body = json.dumps({"name": "RTFM actualizado"})
        connection.request(
            "PUT", "/api/v1/integrations/applications/" + item["id"],
            body=body,
            headers={
                "Cookie": cookie,
                "X-CSRF-Token": csrf,
                "Content-Type": "application/json",
            },
        )
        updated = connection.getresponse()
        self.assertEqual(200, updated.status)
        updated.read()

        connection.request(
            "DELETE", "/api/v1/integrations/applications/" + item["id"],
            headers={"Cookie": cookie, "X-CSRF-Token": csrf},
        )
        deleted = connection.getresponse()
        self.assertEqual(200, deleted.status)
        deleted.read()
        connection.close()

    def test_first_account_setup_is_public_once(self):
        with tempfile.TemporaryDirectory() as directory:
            server = GuardianServer(
                ("127.0.0.1", 0),
                FakeManager(directory),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:" + str(server.server_port) + "/api/v1/auth/setup"
                payload = {
                    "username": "owner",
                    "display_name": "Owner",
                    "allow_insecure_portal": False,
                    "password": "Owner-Chosen-Password-882",
                    "password_confirmation": "Owner-Chosen-Password-882",
                }
                request = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    body = json.loads(response.read())
                    self.assertEqual(201, response.status)
                    self.assertIn("HttpOnly", response.headers["Set-Cookie"])
                    self.assertIn("Secure", response.headers["Set-Cookie"])
                self.assertEqual("owner", body["session"]["username"])
                with self.assertRaises(urllib.error.HTTPError) as context:
                    urllib.request.urlopen(request, timeout=2)
                self.assertEqual(409, context.exception.code)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_readiness_returns_503_with_machine_readable_reasons(self):
        status, body = self.request(
            "/api/v1/instances/vaultwarden-1/readiness",
        )
        self.assertEqual(status, 503)
        self.assertFalse(body["ready"])
        self.assertEqual(body["reasons"], ["missing_fingerprint"])

    def test_portal_session_authenticates_and_requires_csrf_for_changes(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3)
        payload = json.dumps({
            "username": "admin",
            "password": "Correct-Horse-Battery-77",
        })
        connection.request(
            "POST", "/api/v1/session", body=payload,
            headers={"Content-Type": "application/json"},
        )
        login = connection.getresponse()
        self.assertEqual(200, login.status)
        cookie = login.getheader("Set-Cookie").split(";", 1)[0]
        session = json.loads(login.read())["session"]
        self.assertIn("HttpOnly", login.getheader("Set-Cookie"))

        connection.request(
            "GET", "/api/v1/admin", headers={"Cookie": cookie})
        authorized = connection.getresponse()
        self.assertEqual(200, authorized.status)
        authorized.read()

        policy = json.dumps({
            "mode": "observe",
            "interval_seconds": 30,
            "backup_retention": 5,
            "max_package_mb": 256,
        })
        connection.request(
            "PUT", "/api/v1/cluster/policy", body=policy,
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        missing_csrf = connection.getresponse()
        self.assertEqual(401, missing_csrf.status)
        missing_csrf.read()

        connection.request(
            "PUT", "/api/v1/cluster/policy", body=policy,
            headers={
                "Cookie": cookie,
                "Content-Type": "application/json",
                "X-CSRF-Token": session["csrf_token"],
            },
        )
        changed = connection.getresponse()
        self.assertEqual(200, changed.status)
        changed.read()
        connection.close()

    def test_backups_route_still_requires_admin_token(self):
        status, body = self.request("/api/v1/instances/vaultwarden-1/backups")
        self.assertEqual(status, 401)
        self.assertIn("error", body)

    def test_backups_route_remains_available_after_readiness_route(self):
        status, body = self.request(
            "/api/v1/instances/vaultwarden-1/backups",
            "admin-token",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["instance"], "vaultwarden-1")

    def test_sync_consumes_an_optional_body_on_persistent_connections(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_port,
            timeout=2,
        )
        connection.request(
            "POST",
            "/api/v1/instances/vaultwarden-1/sync",
            body="{}",
            headers={
                "Authorization": "Bearer admin-token",
                "Content-Type": "application/json",
            },
        )
        first = connection.getresponse()
        self.assertEqual(first.status, 200)
        first.read()
        connection.request("GET", "/api/health")
        second = connection.getresponse()
        self.assertEqual(second.status, 200)
        second.read()
        connection.close()

    def test_unauthorized_sync_is_rejected_before_reading_its_body(self):
        with mock.patch(
            "server.GuardianHandler._discard_body",
            side_effect=AssertionError("an unauthenticated body was read"),
        ):
            status, body = self.request(
                "/api/v1/instances/vaultwarden-1/sync",
                method="POST",
                body={},
            )
        self.assertEqual(status, 401)
        self.assertEqual(body["code"], "AUTH_REQUIRED")

    def test_session_rejects_ambiguous_or_chunked_http_framing(self):
        cases = (
            (
                [("Content-Length", "2"), ("Content-Length", "2")],
                b"{}",
            ),
            (
                [("Transfer-Encoding", "chunked")],
                b"2\r\n{}\r\n0\r\n\r\n",
            ),
        )
        for headers, body in cases:
            with self.subTest(headers=headers):
                status, connection, payload = self.raw_session_request(
                    headers, body)
                self.assertEqual(400, status)
                self.assertEqual("close", connection)
                self.assertEqual("REQUEST_ERROR", payload["code"])

    def test_large_replication_bodies_are_serialized(self):
        path = "/api/v1/internal/provisioning/provision:12345678/snapshot"
        self.assertTrue(self.server.large_body_slots.acquire(blocking=False))
        try:
            with mock.patch("server.REQUEST_TIMEOUT_SECONDS", 0.01):
                status, body = self.request(
                    path,
                    method="POST",
                    body={"encrypted": "package"},
                    internal_token="replication-token",
                )
        finally:
            self.server.large_body_slots.release()
        self.assertEqual(503, status)
        self.assertEqual("SERVER_BUSY", body["code"])

        status, body = self.request(
            path,
            method="POST",
            body={"encrypted": "package"},
            internal_token="replication-token",
        )
        self.assertEqual(200, status)
        self.assertEqual("data_applied", body["stage"])

    def test_cluster_policy_requires_admin_and_updates_the_group(self):
        payload = {
            "mode": "observe",
            "interval_seconds": 30,
            "backup_retention": 5,
            "max_package_mb": 256,
        }
        status, _ = self.request(
            "/api/v1/cluster/policy", method="PUT", body=payload
        )
        self.assertEqual(status, 401)
        status, body = self.request(
            "/api/v1/cluster/policy",
            token="admin-token",
            method="PUT",
            body=payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["estado"], "aplicado_en_grupo")

    def test_cluster_configuration_distributes_the_existing_identity(self):
        status, body = self.request(
            "/api/v1/cluster/configuration",
            token="admin-token",
            method="PUT",
            body={
                "local_name": "node-1",
                "members": [{
                    "name": "node-1",
                    "guardian_url": "http://192.0.2.10:6062",
                    "node_ip": "192.0.2.10",
                    "floating_api": "http://192.0.2.10:6060",
                }],
            },
        )
        self.assertEqual(200, status)
        self.assertEqual("grupo_configurado", body["estado"])
        self.assertEqual({"updated": [], "failed": {}}, body["identidades"])

    def test_replication_token_can_read_peer_status_but_not_mutate_admin_api(self):
        status, body = self.request(
            "/api/v1/status", internal_token="replication-token",
        )
        self.assertEqual(200, status)
        self.assertEqual("node-1", body["nodo"])

        admin_reads = (
            "/api/status",
            "/api/v1/users",
            "/metrics",
            "/api/v1/metrics",
            "/api/v1/cluster",
            "/api/v1/history",
            "/api/v1/config",
            "/api/v1/setup",
            "/api/v1/discovery",
            "/api/v1/provisioning/candidates",
            "/api/v1/provisioning/transactions/provision:12345678",
            "/api/v1/admin",
            "/api/v1/instances",
            "/api/v1/instances/vaultwarden-1/backups",
            "/api/v1/instances/vaultwarden-1",
        )
        for path in admin_reads:
            with self.subTest(path=path):
                status, _ = self.request(
                    path, internal_token="replication-token",
                )
                self.assertEqual(401, status)

        status, _ = self.request(
            "/api/v1/instances/validate",
            method="POST",
            body={},
            internal_token="replication-token",
        )
        self.assertEqual(401, status)

    def test_internal_sync_only_accepts_the_replication_token(self):
        status, _ = self.request(
            "/api/v1/internal/sync/vaultwarden-1", method="POST", body={}
        )
        self.assertEqual(status, 401)
        status, body = self.request(
            "/api/v1/internal/sync/vaultwarden-1",
            method="POST", body={}, internal_token="replication-token",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["instance"], "vaultwarden-1")

    def test_reconciliation_separates_admin_and_internal_authority(self):
        status, _ = self.request(
            "/api/v1/reconciliation",
            method="POST",
            body={"confirm": True},
        )
        self.assertEqual(401, status)
        status, body = self.request(
            "/api/v1/reconciliation",
            token="admin-token",
            method="POST",
            body={"confirm": True},
        )
        self.assertEqual(200, status)
        self.assertEqual("reconciliado", body["estado"])
        self.assertTrue(body["confirm"])

        internal = {
            "instance_id": "vaultwarden-1",
            "target": "node-3",
            "transaction": "backfill-12345678",
        }
        status, _ = self.request(
            "/api/v1/internal/reconciliation",
            method="POST",
            body=internal,
        )
        self.assertEqual(401, status)
        status, body = self.request(
            "/api/v1/internal/reconciliation",
            method="POST",
            body=internal,
            internal_token="replication-token",
        )
        self.assertEqual(200, status)
        self.assertTrue(body["complete"])
        self.assertEqual("node-3", body["target_node"])

    def test_provisioning_routes_separate_admin_and_internal_authority(self):
        admin_path = "/api/v1/provisioning"
        payload = {
            "instance_id": "vaultwarden-1",
            "source_container": "vaultwarden-source",
            "confirm": True,
        }
        status, _ = self.request(
            admin_path, method="POST", body=payload)
        self.assertEqual(401, status)
        status, body = self.request(
            admin_path,
            token="admin-token",
            method="POST",
            body=payload,
            idempotency="provision:test-123",
        )
        self.assertEqual(201, status)
        self.assertTrue(body["complete"])
        self.assertEqual("provision:test-123", body["transaction"])

        path = "/api/v1/internal/provisioning/preflight"
        status, _ = self.request(path, method="POST", body={"format": 1})
        self.assertEqual(401, status)
        status, body = self.request(
            path,
            method="POST",
            body={"format": 1},
            internal_token="replication-token",
        )
        self.assertEqual(200, status)
        self.assertEqual("validated", body["stage"])

        status, body = self.request(
            "/api/v1/internal/provisioning/prepare",
            method="POST",
            body={"format": 1},
            internal_token="replication-token",
        )
        self.assertEqual(201, status)
        self.assertEqual("prepared", body["stage"])

        transaction = "provision:12345678"
        status, body = self.request(
            f"/api/v1/internal/provisioning/{transaction}/snapshot",
            method="POST",
            body={"encrypted": "package"},
            internal_token="replication-token",
        )
        self.assertEqual(200, status)
        self.assertEqual("data_applied", body["stage"])
        self.assertGreater(body["bytes"], 0)

        status, body = self.request(
            f"/api/v1/internal/provisioning/{transaction}/activate",
            method="POST",
            body={},
            internal_token="replication-token",
        )
        self.assertEqual(200, status)
        self.assertEqual("registered", body["stage"])

        status, _ = self.request(
            f"/api/v1/provisioning/transactions/{transaction}")
        self.assertEqual(401, status)
        status, body = self.request(
            f"/api/v1/provisioning/transactions/{transaction}",
            token="admin-token",
        )
        self.assertEqual(200, status)
        self.assertEqual("registered", body["stage"])


if __name__ == "__main__":
    unittest.main()

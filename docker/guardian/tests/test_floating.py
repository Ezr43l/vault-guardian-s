import json
import unittest
from unittest import mock

import floating

TOKEN = "fip_" + ("0" * 32) + "_" + ("x" * 43)


class Response:
    def __init__(self, payload):
        self.status = 200
        self.body = json.dumps(payload).encode("utf-8")


class FloatingClientTests(unittest.TestCase):
    def test_claim_sends_idempotency_key_and_reports_partial_propagation(self):
        response = {
            "reclamacion": {
                "ip": "192.0.2.40",
                "servicio": "vaultwarden-1",
            },
            "repetida": False,
            "local": {"recargado": True},
            "pares": {
                "http://192.0.2.11:6060": "ok",
                "http://192.0.2.12:6060": "falló: TimeoutError",
            },
        }
        with mock.patch(
            "floating.http_client.request",
            return_value=Response(response),
        ) as request:
            result = floating.claim(
                "http://192.0.2.10:6060",
                api_token=TOKEN,
                idempotency_key="provision:00000001",
                service="vaultwarden-1",
                description="Vaultwarden 1",
                ports=[5743],
                health_port=5743,
                health_path="/alive",
                allow_insecure_http=True,
            )

        self.assertEqual("POST", request.call_args.kwargs["method"])
        self.assertEqual(
            "provision:00000001",
            request.call_args.kwargs["headers"]["Idempotency-Key"],
        )
        self.assertEqual(
            f"Bearer {TOKEN}",
            request.call_args.kwargs["headers"]["Authorization"],
        )
        self.assertEqual(
            "vaultwarden-1",
            json.loads(request.call_args.kwargs["body"].decode("utf-8"))["servicio"],
        )
        self.assertEqual("192.0.2.40", result["ip"])
        self.assertFalse(result["converged"])

    def test_claim_is_converged_when_local_and_all_peers_accept_it(self):
        with mock.patch(
            "floating.http_client.request",
            return_value=Response({
                "reclamacion": {
                    "ip": "192.0.2.40",
                    "servicio": "vaultwarden-1",
                },
                "repetida": True,
                "local": {"sin_cambios": True},
                "pares": {"http://192.0.2.11:6060": "ok"},
            }),
        ):
            result = floating.claim(
                "http://192.0.2.10:6060",
                api_token=TOKEN,
                idempotency_key="provision:00000002",
                service="vaultwarden-1",
                description="Vaultwarden 1",
                ports=[5743],
                health_port=5743,
                health_path="/alive",
                allow_insecure_http=True,
            )

        self.assertTrue(result["repeated"])
        self.assertTrue(result["converged"])

    def test_release_uses_the_claim_key_and_is_idempotent(self):
        with mock.patch(
            "floating.http_client.request",
            return_value=Response({
                "ip": "192.0.2.40",
                "liberada": True,
                "repetida": True,
                "local": {"sin_cambios": True},
                "pares": {},
            }),
        ) as request:
            result = floating.release_claim(
                "http://192.0.2.10:6060",
                "provision:00000003",
                api_token=TOKEN,
                allow_insecure_http=True,
            )

        self.assertEqual("DELETE", request.call_args.kwargs["method"])
        self.assertTrue(request.call_args.args[1].endswith(
            "/api/claims/provision:00000003"))
        self.assertTrue(result["released"])
        self.assertTrue(result["repeated"])
        self.assertTrue(result["converged"])

    def test_state_uses_bearer_and_reads_the_confirmed_porter(self):
        with mock.patch(
            "floating.http_client.request",
            return_value=Response({
                "direcciones": [{
                    "servicio": "vaultwarden-1",
                    "portador": "node-2",
                    "nodos": {
                        "node-1": {"sano": True, "detalle": "ok"},
                    },
                }],
            }),
        ) as request:
            result = floating.get_state(
                "http://192.0.2.10:6060",
                "vaultwarden-1",
                "node-1",
                api_token=TOKEN,
                allow_insecure_http=True,
            )

        self.assertEqual(
            f"Bearer {TOKEN}",
            request.call_args.kwargs["headers"]["Authorization"],
        )
        self.assertTrue(result.known)
        self.assertEqual("node-2", result.portador)
        self.assertTrue(result.local_healthy)

    def test_missing_token_fails_before_opening_a_connection(self):
        with mock.patch("floating.http_client.request") as request:
            with self.assertRaisesRegex(
                floating.FloatingError,
                "VG_FLOATING_API_TOKEN",
            ):
                floating.get_state(
                    "http://192.0.2.10:6060",
                    "vaultwarden-1",
                    "node-1",
                    api_token="",
                )
        request.assert_not_called()

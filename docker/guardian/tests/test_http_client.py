import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import http_client


class _Response:
    def __init__(self, status=200, body=b"{}", length=None):
        self.status = status
        self._body = body
        self._length = str(len(body) if length is None else length)

    def getheader(self, name):
        return self._length if name == "Content-Length" else None

    def read(self, limit):
        return self._body[:limit]


class _Connection:
    response = _Response()
    instances = []

    def __init__(self, host, port, timeout=None, **kwargs):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.kwargs = kwargs
        self.request_call = None
        self.closed = False
        self.__class__.instances.append(self)

    def request(self, method, path, body=None, headers=None):
        self.request_call = (method, path, body, headers)

    def getresponse(self):
        return self.__class__.response

    def close(self):
        self.closed = True


class HttpClientTests(unittest.TestCase):
    def setUp(self):
        _Connection.instances = []
        _Connection.response = _Response()

    def test_base_url_rejects_ssrf_ambiguities_and_plain_http_by_default(self):
        self.assertEqual(
            "https://node.example:6062/prefix",
            http_client.normalize_base_url(
                "https://node.example:6062/prefix/", allow_http=False
            ),
        )
        for value in (
            "file:///etc/passwd",
            "http://user:secret@node.example",
            "https://node.example?target=other",
            "https://node.example#fragment",
            "https://node.example:99999",
            "https://node.example\\@other",
        ):
            with self.subTest(value=value), self.assertRaises(http_client.HttpClientError):
                http_client.normalize_base_url(value, allow_http=False)
        with self.assertRaisesRegex(http_client.HttpClientError, "VG_ALLOW_INSECURE_HTTP"):
            http_client.normalize_base_url("http://node.example:6062", allow_http=False)
        self.assertEqual(
            "http://host.docker.internal:6060",
            http_client.normalize_base_url(
                "http://host.docker.internal:6060", allow_http=False),
        )

    def test_request_connects_directly_and_never_follows_a_redirect(self):
        _Connection.response = _Response(status=302, body=b"redirect")
        with mock.patch.dict(os.environ, {
            "HTTP_PROXY": "http://proxy.invalid:3128",
            "HTTPS_PROXY": "http://proxy.invalid:3128",
            "NO_PROXY": "",
        }), mock.patch.object(http_client.http.client, "HTTPConnection", _Connection):
            with self.assertRaises(http_client.HttpStatusError) as context:
                http_client.request(
                    "http://node.example:6062/base",
                    "/api/status",
                    allow_http=True,
                )
        self.assertEqual(302, context.exception.status)
        connection = _Connection.instances[0]
        self.assertEqual(("node.example", 6062), (connection.host, connection.port))
        self.assertEqual("/base/api/status", connection.request_call[1])
        self.assertTrue(connection.closed)

    def test_response_limit_applies_to_declared_and_streamed_content(self):
        with mock.patch.object(http_client.http.client, "HTTPConnection", _Connection):
            _Connection.response = _Response(body=b"12345", length=5)
            with self.assertRaisesRegex(http_client.HttpClientError, "supera"):
                http_client.request(
                    "http://node.example", "/status", allow_http=True, max_bytes=4
                )
            _Connection.response = _Response(body=b"12345", length=4)
            with self.assertRaisesRegex(http_client.HttpClientError, "supera"):
                http_client.request(
                    "http://node.example", "/status", allow_http=True, max_bytes=4
                )

    def test_private_ca_must_be_an_absolute_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca = root / "ca.pem"
            ca.write_text("not-a-real-ca", encoding="utf-8")
            with mock.patch.object(
                http_client.ssl, "create_default_context", return_value=object()
            ) as create_context:
                http_client._ssl_context(str(ca))
            create_context.assert_called_once_with(cafile=str(ca))
            link = root / "ca-link.pem"
            try:
                link.symlink_to(ca)
            except OSError:
                self.skipTest("el sistema no permite crear symlinks")
            with self.assertRaisesRegex(http_client.HttpClientError, "regular"):
                http_client._ssl_context(str(link))


if __name__ == "__main__":
    unittest.main()

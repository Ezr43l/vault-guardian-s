"""Cliente Docker mínimo para el socket local o un endpoint autenticado."""

from __future__ import annotations

import http.client
import json
import re
import socket
from urllib.parse import quote, urlencode, urlsplit


class DockerError(RuntimeError):
    """Docker no pudo completar una operación permitida."""


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 15):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:  # pragma: no cover - requiere Linux + socket Docker
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def _http_endpoint(value: str) -> tuple[str, int]:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(ord(char) < 33 for char in parsed.hostname)
    ):
        raise DockerError("endpoint Docker remoto no válido")
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise DockerError("puerto no válido en el endpoint Docker") from exc
    return parsed.hostname, port


class DockerClient:
    """Implementa exclusivamente las operaciones que usa Vault Guardian."""

    def __init__(
        self,
        endpoint: str = "/var/run/docker.sock",
        control_token: str | None = None,
        *,
        allow_local_socket: bool = True,
    ):
        self.endpoint = endpoint
        self.control_token = control_token or ""
        self.allow_local_socket = allow_local_socket

    def _connection(self, timeout: float) -> http.client.HTTPConnection:
        if self.endpoint.startswith("/"):
            if not self.allow_local_socket:
                raise DockerError("el proceso web no puede usar el socket Docker directo")
            return _UnixConnection(self.endpoint, timeout=timeout)
        host, port = _http_endpoint(self.endpoint)
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> tuple[int, bytes]:
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise DockerError("ruta Docker no válida")
        connection = self._connection(timeout)
        try:
            request_headers = {"Connection": "close", **(headers or {})}
            if body is None:
                request_headers.setdefault("Content-Length", "0")
            if not self.endpoint.startswith("/"):
                if not 32 <= len(self.control_token) <= 4096:
                    raise DockerError("falta un token válido para el endpoint Docker remoto")
                request_headers["Authorization"] = f"Bearer {self.control_token}"
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            length = response.getheader("Content-Length")
            if length:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise DockerError("Docker devolvió Content-Length no válido") from exc
                if declared < 0 or declared > max_bytes:
                    raise DockerError("respuesta de Docker demasiado grande")
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise DockerError("respuesta de Docker demasiado grande")
            return response.status, payload
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(f"Docker no disponible: {type(exc).__name__}") from exc
        finally:
            connection.close()

    @staticmethod
    def _decode_json(body: bytes, operation: str):
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise DockerError(f"respuesta no válida de Docker {operation}") from exc

    @staticmethod
    def _error(operation: str, status: int, body: bytes) -> DockerError:
        detail = ""
        try:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, dict):
                detail = str(payload.get("message") or payload.get("error") or "")[:500]
        except (ValueError, UnicodeDecodeError):
            pass
        suffix = f": {detail}" if detail else ""
        return DockerError(f"Docker {operation} devolvió {status}{suffix}")

    def ping(self) -> None:
        status, _ = self._request("GET", "/_ping", max_bytes=64)
        if status != 200:
            raise DockerError(f"Docker ping devolvió {status}")

    def inspect_full(self, container: str) -> dict | None:
        status, body = self._request(
            "GET", f"/containers/{quote(container, safe='')}/json"
        )
        if status == 404:
            return None
        if status >= 300:
            raise self._error("inspect", status, body)
        payload = self._decode_json(body, "inspect")
        if not isinstance(payload, dict):
            raise DockerError("respuesta no válida de Docker inspect")
        return payload

    def inspect(self, container: str) -> dict:
        payload = self.inspect_full(container)
        if payload is None:
            return {"existe": False}
        return {
            "existe": True,
            "estado": (payload.get("State") or {}).get("Status"),
            "en_marcha": bool((payload.get("State") or {}).get("Running")),
        }

    def containers(self) -> list[dict]:
        status, body = self._request("GET", "/containers/json?all=1")
        if status >= 300:
            raise self._error("list", status, body)
        payload = self._decode_json(body, "list")
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise DockerError("respuesta no válida de Docker list")
        return payload

    def inspect_image(self, image: str) -> dict | None:
        status, body = self._request("GET", f"/images/{quote(image, safe='')}/json")
        if status == 404:
            return None
        if status >= 300:
            raise self._error("image inspect", status, body)
        payload = self._decode_json(body, "image inspect")
        if not isinstance(payload, dict):
            raise DockerError("respuesta no válida de Docker image inspect")
        return payload

    def pull_image(self, reference: str, timeout: float = 300) -> None:
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 512
            or any(char.isspace() for char in reference)
        ):
            raise DockerError("referencia de imagen no válida")
        name, tag = reference, None
        if "@" in reference:
            name, tag = reference.rsplit("@", 1)
        else:
            last = reference.rsplit("/", 1)[-1]
            if ":" in last:
                name, tag = reference.rsplit(":", 1)
        query = {"fromImage": name}
        if tag:
            query["tag"] = tag
        status, body = self._request(
            "POST",
            "/images/create?" + urlencode(query),
            timeout=timeout,
            max_bytes=64 * 1024 * 1024,
        )
        if status >= 300:
            raise self._error("pull", status, body)
        for line in body.splitlines():
            try:
                event = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(event, dict) and event.get("error"):
                raise DockerError("Docker pull falló")

    def create_container(self, name: str, spec: dict) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name or ""):
            raise DockerError("nombre de contenedor no válido")
        body = json.dumps(spec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > 1024 * 1024:
            raise DockerError("especificación de contenedor demasiado grande")
        status, response = self._request(
            "POST",
            f"/containers/create?{urlencode({'name': name})}",
            body=body,
            headers={"Content-Type": "application/json"},
            max_bytes=1024 * 1024,
        )
        if status != 201:
            raise self._error("create", status, response)
        payload = self._decode_json(response, "create")
        identifier = str(payload.get("Id") or "") if isinstance(payload, dict) else ""
        if not identifier:
            raise DockerError("Docker create no devolvió id")
        return identifier

    def remove(self, container: str, *, force: bool = False) -> None:
        query = urlencode({"force": str(force).lower(), "v": "false"})
        status, body = self._request(
            "DELETE", f"/containers/{quote(container, safe='')}?{query}"
        )
        if status not in (204, 404):
            raise self._error("remove", status, body)

    def wait(self, container: str, timeout: float = 300) -> int:
        status, body = self._request(
            "POST",
            f"/containers/{quote(container, safe='')}/wait?condition=not-running",
            timeout=timeout,
            max_bytes=1024 * 1024,
        )
        if status != 200:
            raise self._error("wait", status, body)
        payload = self._decode_json(body, "wait")
        try:
            return int(payload["StatusCode"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DockerError("Docker wait no devolvió StatusCode") from exc

    def logs(self, container: str, max_bytes: int = 64 * 1024) -> str:
        status, body = self._request(
            "GET",
            f"/containers/{quote(container, safe='')}/logs?stdout=1&stderr=1",
            max_bytes=max_bytes,
        )
        if status >= 300:
            raise self._error("logs", status, body)
        output = bytearray()
        offset = 0
        while offset + 8 <= len(body) and body[offset] in (0, 1, 2):
            size = int.from_bytes(body[offset + 4 : offset + 8], "big")
            start, end = offset + 8, offset + 8 + size
            if end > len(body):
                break
            output.extend(body[start:end])
            offset = end
        if not output:
            output.extend(body)
        return output.decode("utf-8", errors="replace")

    def get_archive(self, container: str, path: str, max_bytes: int) -> bytes:
        status, body = self._request(
            "GET",
            f"/containers/{quote(container, safe='')}/archive?{urlencode({'path': path})}",
            max_bytes=max_bytes,
        )
        if status != 200:
            raise self._error("get archive", status, body)
        return body

    def put_archive(self, container: str, path: str, archive: bytes) -> None:
        if len(archive) > 1024 * 1024 * 1024:
            raise DockerError("archivo de entrada demasiado grande")
        status, body = self._request(
            "PUT",
            f"/containers/{quote(container, safe='')}/archive?{urlencode({'path': path})}",
            body=archive,
            headers={"Content-Type": "application/x-tar"},
            max_bytes=1024 * 1024,
            timeout=300,
        )
        if status != 200:
            raise self._error("put archive", status, body)

    def stop(self, container: str, timeout: int = 15) -> None:
        status, body = self._request(
            "POST", f"/containers/{quote(container, safe='')}/stop?t={timeout}",
            timeout=timeout + 15,
        )
        if status not in (204, 304):
            raise self._error("stop", status, body)

    def start(self, container: str) -> None:
        status, body = self._request(
            "POST", f"/containers/{quote(container, safe='')}/start"
        )
        if status not in (204, 304):
            raise self._error("start", status, body)

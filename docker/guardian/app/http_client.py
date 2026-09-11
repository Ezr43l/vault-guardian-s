"""Cliente HTTP saliente estricto para servicios internos de Vault Guardian."""

from __future__ import annotations

import http.client
import ipaddress
import os
import re
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class HttpClientError(RuntimeError):
    """La petición no puede realizarse dentro de la política de red."""


class HttpStatusError(HttpClientError):
    """El destino respondió con un estado HTTP no satisfactorio."""

    def __init__(self, status: int, body: bytes = b""):
        super().__init__(f"el destino respondió HTTP {status}")
        self.status = status
        self.body = body


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


_HOST_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})
_MAX_CA_BYTES = 4 * 1024 * 1024


def validate_host(value: str, label: str = "host") -> str:
    """Valida una IP o nombre DNS sin permitir componentes de URL."""
    host = str(value or "").strip()
    if not host or len(host) > 253 or any(
        character in host for character in "/?#@\\\x00\r\n\t "
    ):
        raise HttpClientError(f"{label} no es una IP o nombre DNS válido")
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if ":" in candidate:
        raise HttpClientError(f"{label} no es una IP o nombre DNS válido")
    labels = candidate.rstrip(".").split(".")
    if not labels or any(not _HOST_LABEL.fullmatch(item) for item in labels):
        raise HttpClientError(f"{label} no es una IP o nombre DNS válido")
    return candidate.rstrip(".")


def normalize_base_url(value: str, *, allow_http: bool, label: str = "URL") -> str:
    """Normaliza una base HTTP(S) sin credenciales, query ni fragmento."""
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise HttpClientError(f"{label} contiene un puerto no válido") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HttpClientError(f"{label} debe ser una URL HTTP(S) válida")
    if parsed.username is not None or parsed.password is not None:
        raise HttpClientError(f"{label} no admite credenciales embebidas")
    if parsed.query or parsed.fragment:
        raise HttpClientError(f"{label} no admite query ni fragmento")
    if any(character in raw for character in "\x00\r\n\t\\"):
        raise HttpClientError(f"{label} contiene caracteres no permitidos")
    validate_host(parsed.hostname, label)
    if port is not None and not 1 <= port <= 65535:
        raise HttpClientError(f"{label} contiene un puerto no válido")
    local_transport = (parsed.hostname or "").lower() in {
        "127.0.0.1", "::1", "localhost", "host.docker.internal",
    }
    if parsed.scheme == "http" and not (allow_http or local_transport):
        raise HttpClientError(
            f"{label} usa HTTP; configura HTTPS o acepta el riesgo con "
            "VG_ALLOW_INSECURE_HTTP=true"
        )
    path = parsed.path.rstrip("/")
    if path and (not path.startswith("/") or "//" in path or any(
        item in {".", ".."} for item in path.split("/")
    )):
        raise HttpClientError(f"{label} contiene una ruta base no válida")
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    authority = host if port is None else f"{host}:{port}"
    return f"{parsed.scheme}://{authority}{path}"


def origin_for_host(host: str, port: int, *, allow_http: bool, label: str = "host") -> str:
    validated = validate_host(host, label)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise HttpClientError(f"puerto no válido para {label}")
    authority = f"[{validated}]" if ":" in validated else validated
    return normalize_base_url(
        f"http://{authority}:{port}", allow_http=allow_http, label=label
    )


def _request_target(base_path: str, path: str) -> str:
    candidate = str(path or "")
    parsed = urlsplit(candidate)
    if (not candidate.startswith("/") or candidate.startswith("//")
            or parsed.scheme or parsed.netloc or parsed.fragment
            or any(character in candidate for character in "\x00\r\n\t\\ ")):
        raise HttpClientError("ruta HTTP no válida")
    target = f"{base_path.rstrip('/')}{parsed.path}"
    return f"{target}?{parsed.query}" if parsed.query else target


def _ssl_context(ca_file: str | None) -> ssl.SSLContext:
    if not ca_file:
        return ssl.create_default_context()
    path = Path(ca_file)
    if not path.is_absolute():
        raise HttpClientError("VG_CA_FILE debe ser una ruta absoluta")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HttpClientError("no se puede leer VG_CA_FILE") from exc
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_CA_BYTES):
        raise HttpClientError("VG_CA_FILE debe ser un fichero regular y acotado")
    try:
        return ssl.create_default_context(cafile=os.fspath(path))
    except (OSError, ssl.SSLError) as exc:
        raise HttpClientError("no se puede cargar VG_CA_FILE") from exc


def _read_limited(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    length = response.getheader("Content-Length")
    if length is not None:
        try:
            declared = int(length)
        except ValueError as exc:
            raise HttpClientError("el destino devolvió Content-Length no válido") from exc
        if declared < 0 or declared > max_bytes:
            raise HttpClientError("la respuesta HTTP supera el límite permitido")
    body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise HttpClientError("la respuesta HTTP supera el límite permitido")
    return body


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5,
    max_bytes: int = 1024 * 1024,
    allow_http: bool = False,
    ca_file: str | None = None,
) -> HttpResponse:
    """Realiza una petición directa, sin proxy ni seguimiento de redirecciones."""
    verb = str(method or "").upper()
    if verb not in _METHODS:
        raise HttpClientError("método HTTP no permitido")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise HttpClientError("límite de respuesta no válido")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise HttpClientError("timeout HTTP no válido")
    normalized = normalize_base_url(base_url, allow_http=allow_http)
    parsed = urlsplit(normalized)
    target = _request_target(parsed.path, path)
    connection: http.client.HTTPConnection
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=_ssl_context(ca_file),
        )
    else:
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port or 80, timeout=timeout
        )
    request_headers = {"Connection": "close", "Accept": "application/json"}
    request_headers.update(headers or {})
    try:
        connection.request(verb, target, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = _read_limited(response, max_bytes)
        if response.status < 200 or response.status >= 300:
            raise HttpStatusError(response.status, payload)
        return HttpResponse(response.status, payload)
    except HttpClientError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        raise HttpClientError(f"el destino HTTP no responde: {type(exc).__name__}") from exc
    finally:
        connection.close()

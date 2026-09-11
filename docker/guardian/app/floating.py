"""Cliente estricto para consultar y reclamar direcciones en floating-ip."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

import http_client


class FloatingError(RuntimeError):
    """No se pudo obtener un estado fiable de la VIP."""


@dataclass(frozen=True)
class FloatingState:
    service: str
    known: bool
    portador: str | None = None
    local_healthy: bool | None = None
    detail: str | None = None

    @property
    def is_active(self) -> bool:
        return self.known and self.portador is not None

    def is_node_active(self, node: str) -> bool:
        return self.is_active and self.portador == node

    def as_dict(self) -> dict:
        return {
            "servicio": self.service,
            "conocido": self.known,
            "portador": self.portador,
            "salud_local": self.local_healthy,
            "detalle": self.detail,
        }


def _request(
    base_url: str,
    path: str,
    *,
    api_token: str,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> dict:
    body = None
    token = api_token.strip()
    if not token:
        raise FloatingError("falta VG_FLOATING_API_TOKEN")
    request_headers = {
        "Accept": "application/json",
        **(headers or {}),
        "Authorization": f"Bearer {token}",
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request_headers["Content-Type"] = "application/json; charset=utf-8"
    try:
        response = http_client.request(
            base_url,
            path,
            method=method,
            body=body,
            headers=request_headers,
            timeout=timeout,
            max_bytes=2 * 1024 * 1024,
            allow_http=allow_insecure_http,
            ca_file=ca_file,
        )
        result = json.loads(response.body.decode("utf-8") or "{}")
    except http_client.HttpStatusError as exc:
        detail = ""
        try:
            error_payload = json.loads(exc.body[:64 * 1024].decode("utf-8"))
            detail = str(error_payload.get("error") or "")
        except (ValueError, UnicodeDecodeError, AttributeError):
            pass
        suffix = f": {detail}" if detail else ""
        raise FloatingError(
            f"floating-ip rechazó la petición ({exc.status}){suffix}") from exc
    except (http_client.HttpClientError, ValueError, UnicodeDecodeError) as exc:
        raise FloatingError(f"floating-ip no responde: {type(exc).__name__}") from exc
    if not isinstance(result, dict):
        raise FloatingError("floating-ip devolvió una respuesta no válida")
    return result


def get_addresses(
    base_url: str,
    *,
    api_token: str,
    timeout: float = 5,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> dict:
    result = _request(
        base_url, "/api/direcciones", api_token=api_token, timeout=timeout,
        allow_insecure_http=allow_insecure_http, ca_file=ca_file)
    if not isinstance(result.get("direcciones"), list):
        raise FloatingError("floating-IP no devolvió sus direcciones")
    return result


def claim(
    base_url: str,
    *,
    api_token: str,
    idempotency_key: str,
    service: str,
    description: str,
    ports: list[int],
    health_port: int,
    health_path: str,
    timeout: float = 15,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> dict:
    """Reclama una IP sin elegir el servidor que la sostendrá."""
    result = _request(
        base_url,
        "/api/claims",
        api_token=api_token,
        method="POST",
        payload={
            "servicio": service,
            "descripcion": description,
            "puertos": ports,
            "chequeo": {"puerto": health_port, "ruta": health_path},
        },
        headers={"Idempotency-Key": idempotency_key},
        timeout=timeout,
        allow_insecure_http=allow_insecure_http,
        ca_file=ca_file,
    )
    address = result.get("reclamacion")
    if not isinstance(address, dict) or not address.get("ip"):
        raise FloatingError("floating-ip no confirmó la dirección reclamada")
    peers = result.get("pares") or {}
    local = result.get("local") or {}
    if not isinstance(peers, dict) or not isinstance(local, dict):
        raise FloatingError("floating-ip devolvió una confirmación incompleta")
    return {
        "ip": address["ip"],
        "service": address.get("servicio"),
        "repeated": bool(result.get("repetida")),
        "local": local,
        "peers": peers,
        "converged": (
            not local.get("error")
            and all(value == "ok" for value in peers.values())
        ),
    }


def release_claim(
    base_url: str,
    idempotency_key: str,
    *,
    api_token: str,
    timeout: float = 15,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> dict:
    result = _request(
        base_url,
        f"/api/claims/{quote(idempotency_key, safe='._:-')}",
        api_token=api_token,
        method="DELETE",
        timeout=timeout,
        allow_insecure_http=allow_insecure_http,
        ca_file=ca_file,
    )
    peers = result.get("pares") or {}
    local = result.get("local") or {}
    return {
        "ip": result.get("ip"),
        "released": bool(result.get("liberada")),
        "repeated": bool(result.get("repetida")),
        "local": local,
        "peers": peers,
        "converged": (
            isinstance(local, dict)
            and isinstance(peers, dict)
            and not local.get("error")
            and all(value == "ok" for value in peers.values())
        ),
    }


def get_state(
    base_url: str,
    service: str,
    node: str,
    *,
    api_token: str,
    timeout: float = 5,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> FloatingState:
    payload = get_addresses(
        base_url, api_token=api_token, timeout=timeout,
        allow_insecure_http=allow_insecure_http, ca_file=ca_file)
    for address in payload.get("direcciones", []):
        if address.get("servicio") != service:
            continue
        node_view = (address.get("nodos") or {}).get(node) or {}
        return FloatingState(
            service=service,
            known=True,
            portador=address.get("portador"),
            local_healthy=node_view.get("sano"),
            detail=node_view.get("detalle"),
        )
    return FloatingState(service=service, known=False, detail="servicio no declarado")

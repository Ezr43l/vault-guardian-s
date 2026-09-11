"""Configuración operativa persistente y editable desde el asistente."""

from __future__ import annotations

import json
import os
import posixpath
import re
from pathlib import Path

import http_client


class RuntimeConfigError(ValueError):
    pass


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_ALLOWED = {
    "node",
    "node_ip",
    "peers",
    "floating_api",
    "mode",
    "interval_seconds",
    "backup_retention",
    "max_package_mb",
    "vaultwarden_root",
    "allow_insecure_http",
}


def normalize(raw: dict, *, allow_insecure_http: bool = False) -> dict:
    if not isinstance(raw, dict):
        raise RuntimeConfigError("la configuración debe ser un objeto")
    unknown = sorted(set(raw) - _ALLOWED)
    if unknown:
        raise RuntimeConfigError("campos no permitidos: " + ", ".join(unknown))
    configured_allow_http = raw.get("allow_insecure_http", allow_insecure_http)
    if type(configured_allow_http) is not bool:
        raise RuntimeConfigError("allow_insecure_http debe ser true o false")

    node = str(raw.get("node", "")).strip()
    if not _NAME.fullmatch(node):
        raise RuntimeConfigError("node debe ser un identificador estable")
    try:
        node_ip = http_client.validate_host(
            str(raw.get("node_ip", "")).strip(), "node_ip"
        )
        floating_api = http_client.normalize_base_url(
            str(raw.get("floating_api", "")).strip(),
            allow_http=configured_allow_http,
            label="floating_api",
        )
    except http_client.HttpClientError as exc:
        raise RuntimeConfigError(str(exc)) from exc
    mode = str(raw.get("mode", "observe")).strip().lower()
    if mode not in {"observe", "dry-run", "active"}:
        raise RuntimeConfigError("mode debe ser observe, dry-run o active")

    vaultwarden_root = str(raw.get("vaultwarden_root") or "").strip()
    if vaultwarden_root:
        if (
            not vaultwarden_root.startswith("/")
            or vaultwarden_root == "/"
            or any(char in vaultwarden_root for char in ("\x00", "\r", "\n", ":"))
        ):
            raise RuntimeConfigError(
                "vaultwarden_root debe ser una carpeta host absoluta y concreta")
        vaultwarden_root = posixpath.normpath(vaultwarden_root)
        if vaultwarden_root == "/":
            raise RuntimeConfigError(
                "vaultwarden_root no puede resolverse a la raíz del servidor")

    peers_raw = raw.get("peers", {})
    if not isinstance(peers_raw, dict):
        raise RuntimeConfigError("peers debe ser un objeto nombre: URL")
    peers = {}
    for name, value in peers_raw.items():
        name = str(name).strip()
        try:
            url = http_client.normalize_base_url(
                str(value).strip(),
                allow_http=configured_allow_http,
                label=f"URL del par {name or '?'}",
            )
        except http_client.HttpClientError as exc:
            raise RuntimeConfigError(str(exc)) from exc
        if not _NAME.fullmatch(name):
            raise RuntimeConfigError(f"par no válido: {name!r}")
        if name == node:
            raise RuntimeConfigError("peers no puede incluir el propio nodo")
        peers[name] = url

    try:
        interval = int(raw.get("interval_seconds", 30))
        retention = int(raw.get("backup_retention", 5))
        max_package_mb = int(raw.get("max_package_mb", 256))
    except (TypeError, ValueError) as exc:
        raise RuntimeConfigError("intervalo, retención o tamaño no válidos") from exc
    if interval < 5 or interval > 86400:
        raise RuntimeConfigError("interval_seconds debe estar entre 5 y 86400")
    if retention < 1 or retention > 1000:
        raise RuntimeConfigError("backup_retention debe estar entre 1 y 1000")
    if max_package_mb < 1 or max_package_mb > 256:
        raise RuntimeConfigError("max_package_mb debe estar entre 1 y 256")

    return {
        "node": node,
        "node_ip": node_ip,
        "peers": dict(sorted(peers.items())),
        "floating_api": floating_api,
        "mode": mode,
        "interval_seconds": interval,
        "backup_retention": retention,
        "max_package_mb": max_package_mb,
        "vaultwarden_root": vaultwarden_root,
        "allow_insecure_http": configured_allow_http,
    }


def read(path: Path, *, allow_insecure_http: bool = False) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeConfigError("settings.json no se puede leer") from exc
    if not isinstance(payload, dict) or payload.get("format") != 1:
        raise RuntimeConfigError("settings.json requiere format=1")
    return normalize(
        {key: value for key, value in payload.items() if key != "format"},
        allow_insecure_http=allow_insecure_http,
    )


def write(path: Path, raw: dict, *, allow_insecure_http: bool = False) -> dict:
    normalized = normalize(raw, allow_insecure_http=allow_insecure_http)
    payload = {"format": 1, **normalized}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return normalized

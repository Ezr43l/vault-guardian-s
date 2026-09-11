"""Sobres cifrados para datos sensibles entre Guardian."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken


class SealedError(ValueError):
    pass


def _fernet(token: str) -> Fernet:
    if not isinstance(token, str) or len(token) < 32:
        raise SealedError("la contraseña entre Guardian debe tener al menos 32 caracteres")
    digest = hashlib.sha256(("vault-guardian:sealed:v1:" + token).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal(payload: dict, token: str, purpose: str) -> dict:
    if not isinstance(payload, dict):
        raise SealedError("el contenido sellado debe ser un objeto")
    if not isinstance(purpose, str) or not purpose:
        raise SealedError("falta el propósito del sobre")
    raw = json.dumps({
        "format": 1,
        "purpose": purpose,
        "payload": payload,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encrypted = _fernet(token).encrypt(raw).decode("ascii")
    return {"format": 1, "sealed": encrypted}


def unseal(envelope: dict, token: str, purpose: str, ttl: int = 300) -> dict:
    if (
        not isinstance(envelope, dict)
        or envelope.get("format") != 1
        or not isinstance(envelope.get("sealed"), str)
    ):
        raise SealedError("sobre cifrado no válido")
    try:
        raw = _fernet(token).decrypt(
            envelope["sealed"].encode("ascii"),
            ttl=ttl,
        )
        decoded = json.loads(raw.decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealedError("sobre no válido, caducado o no descifrable") from exc
    if (
        not isinstance(decoded, dict)
        or decoded.get("format") != 1
        or decoded.get("purpose") != purpose
        or not isinstance(decoded.get("payload"), dict)
    ):
        raise SealedError("el sobre no corresponde a esta operación")
    return decoded["payload"]

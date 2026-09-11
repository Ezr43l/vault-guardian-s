"""Operaciones locales, idempotentes y persistentes para crear una réplica."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass

import data_access
import docker_api
import http_client
import provisioning
import sealed
from config import Instance
from state import StateStore


class LocalProvisioningError(RuntimeError):
    pass


_TRANSACTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ALLOWED = {
    "transaction",
    "source",
    "instance_id",
    "display_name",
    "data_directory",
    "target_path",
    "health_path",
    "include_sends",
    "source_node",
}


@dataclass(frozen=True)
class LocalPlan:
    transaction: str
    source: provisioning.VaultwardenSpec
    instance: Instance
    data_directory: str
    target_path: str
    source_node: str
    request_hash: str


class LocalProvisioner:
    def __init__(self, settings, docker, data: data_access.ContainerData,
                 state: StateStore):
        self.settings = settings
        self.docker = docker
        self.data = data
        self.state = state

    def _decode(self, envelope: dict) -> LocalPlan:
        try:
            raw = sealed.unseal(
                envelope,
                self.settings.replication_token,
                "provisioning-spec",
            )
        except sealed.SealedError as exc:
            raise LocalProvisioningError(str(exc)) from exc
        unknown = sorted(set(raw) - _ALLOWED)
        if unknown:
            raise LocalProvisioningError(
                "campos de provisión no permitidos: " + ", ".join(unknown))
        transaction = str(raw.get("transaction") or "")
        if not _TRANSACTION.fullmatch(transaction):
            raise LocalProvisioningError("identificador de transacción no válido")
        try:
            source = provisioning.VaultwardenSpec.from_private(raw.get("source"))
        except provisioning.ProvisioningError as exc:
            raise LocalProvisioningError(str(exc)) from exc
        identifier = str(raw.get("instance_id") or "")
        data_directory = str(raw.get("data_directory") or "")
        source_node = str(raw.get("source_node") or "")
        if not _NAME.fullmatch(identifier):
            raise LocalProvisioningError("id de instancia no válido")
        if not _NAME.fullmatch(data_directory):
            raise LocalProvisioningError("nombre de carpeta de datos no válido")
        if not _NAME.fullmatch(source_node):
            raise LocalProvisioningError("nodo de origen no válido")
        try:
            requested_target = str(raw.get("target_path") or "").strip()
            target_path = (
                provisioning.exact_target_data_path(requested_target)
                if requested_target
                else provisioning.target_data_path(
                    self.settings.vaultwarden_root, data_directory)
            )
            instance = Instance.from_dict({
                "id": identifier,
                "display_name": raw.get("display_name") or identifier,
                "container": source.container,
                "data_dir": str(
                    self.settings.data_roots[0] / ".docker" / identifier),
                "data_backend": "docker",
                "health_port": source.host_port,
                "health_path": raw.get("health_path") or "/alive",
                "floating_service": identifier,
                "include_sends": raw.get("include_sends", True),
                "replication_enabled": True,
            })
        except (provisioning.ProvisioningError, ValueError) as exc:
            raise LocalProvisioningError(str(exc)) from exc
        request_hash = hashlib.sha256(json.dumps(
            raw, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        return LocalPlan(
            transaction=transaction,
            source=source,
            instance=instance,
            data_directory=data_directory,
            target_path=target_path,
            source_node=source_node,
            request_hash=request_hash,
        )

    @staticmethod
    def _labels(inspected: dict | None) -> dict:
        labels = ((inspected or {}).get("Config") or {}).get("Labels") or {}
        return labels if isinstance(labels, dict) else {}

    def _owned(self, inspected: dict | None, transaction: str) -> bool:
        labels = self._labels(inspected)
        return (
            labels.get("com.vault-guardian.managed") == "true"
            and labels.get("com.vault-guardian.transaction") == transaction
        )

    def _base_record(self, plan: LocalPlan, stage: str) -> dict:
        return {
            "stage": stage,
            "request_hash": plan.request_hash,
            "instance": plan.instance.to_dict(),
            "container": plan.instance.container,
            "target_path": plan.target_path,
            "pinned_image": plan.source.pinned_image,
            "host_port": plan.source.host_port,
            "source_node": plan.source_node,
        }

    @staticmethod
    def _public(record: dict, *, repeated: bool = False) -> dict:
        return {
            "transaction": record.get("transaction"),
            "node": record.get("node"),
            "stage": record.get("stage"),
            "instance": (record.get("instance") or {}).get("id"),
            "container": record.get("container"),
            "host_port": record.get("host_port"),
            "image": record.get("pinned_image"),
            "repeated": repeated,
        }

    def _existing_record(self, plan: LocalPlan) -> dict | None:
        try:
            record = self.state.provisioning(plan.transaction)
        except ValueError as exc:
            raise LocalProvisioningError(str(exc)) from exc
        if record and record.get("request_hash") != plan.request_hash:
            raise LocalProvisioningError(
                "la transacción ya existe con una especificación distinta")
        if record and record.get("stage") == "blocked_nonempty":
            raise LocalProvisioningError(
                "la carpeta de destino contiene datos y requiere revisión")
        return record

    def _preflight_collisions(self, plan: LocalPlan,
                              target: dict | None) -> None:
        if target and not self._owned(target, plan.transaction):
            raise LocalProvisioningError(
                f"ya existe el contenedor {plan.instance.container}")
        for summary in self.docker.containers():
            names = summary.get("Names") or []
            name = str(names[0]).lstrip("/") if names else str(summary.get("Id") or "")
            if not name or name == plan.instance.container:
                continue
            inspected = self.docker.inspect_full(name)
            if not inspected:
                continue
            bindings = ((inspected.get("HostConfig") or {})
                        .get("PortBindings") or {})
            for values in bindings.values():
                for binding in values or []:
                    if str((binding or {}).get("HostPort") or "") == str(
                        plan.source.host_port
                    ):
                        raise LocalProvisioningError(
                            f"el puerto {plan.source.host_port} ya está ocupado")
            for mount in inspected.get("Mounts") or []:
                if (
                    isinstance(mount, dict)
                    and mount.get("Source") == plan.target_path
                ):
                    raise LocalProvisioningError(
                        "la carpeta de destino ya está montada por otro contenedor")

    def preflight(self, envelope: dict) -> dict:
        plan = self._decode(envelope)
        record = self._existing_record(plan)
        target = self.docker.inspect_full(plan.instance.container)
        self._preflight_collisions(plan, target)
        if target and not record:
            raise LocalProvisioningError(
                "existe un contenedor de la transacción sin estado persistente")
        if not target:
            try:
                self.data.check_target_directory(plan.target_path)
            except data_access.DataAccessError as exc:
                raise LocalProvisioningError(str(exc)) from exc
        preview = self._base_record(plan, "validated")
        preview["transaction"] = plan.transaction
        preview["node"] = self.settings.node
        return self._public(preview, repeated=bool(record))

    def prepare(self, envelope: dict) -> dict:
        plan = self._decode(envelope)
        record = self._existing_record(plan)
        target = self.docker.inspect_full(plan.instance.container)
        self._preflight_collisions(plan, target)
        if record and record.get("stage") in {
            "prepared", "data_applied", "ready", "registered"
        }:
            if not self._owned(target, plan.transaction):
                raise LocalProvisioningError(
                    "el estado persistente no coincide con el contenedor")
            return self._public(record, repeated=True)
        if target and not record:
            raise LocalProvisioningError(
                "existe un contenedor de la transacción sin estado persistente")

        created = False
        if not target:
            record = self.state.remember_provisioning(
                plan.transaction, self._base_record(plan, "creating"))
            directory_created = False
            try:
                directory_created = self.data.prepare_target_directory(
                    plan.target_path)
                if self.docker.inspect_image(plan.source.pinned_image) is None:
                    self.docker.pull_image(plan.source.pinned_image)
                spec = provisioning.container_create_spec(
                    plan.source,
                    transaction=plan.transaction,
                    target_path=plan.target_path,
                )
                self.docker.create_container(plan.instance.container, spec)
                created = True
                target = self.docker.inspect_full(plan.instance.container)
            except (data_access.DataAccessError, docker_api.DockerError) as exc:
                if directory_created:
                    self.data.discard_created_target(plan.target_path)
                self.state.remember_provisioning(
                    plan.transaction, {**record, "stage": "preparation_failed"})
                raise LocalProvisioningError(str(exc)) from exc
        if not self._owned(target, plan.transaction):
            raise LocalProvisioningError(
                "Docker no confirmó la propiedad del contenedor creado")

        try:
            contents = self.data.inspect_data(
                plan.instance,
                self.settings.replication_token,
                self.settings.max_package_bytes,
            )
        except data_access.DataAccessError as exc:
            raise LocalProvisioningError(str(exc)) from exc
        if not contents["empty"]:
            if created:
                try:
                    self.docker.remove(plan.instance.container, force=True)
                except docker_api.DockerError:
                    pass
            blocked = self.state.remember_provisioning(
                plan.transaction,
                {**self._base_record(plan, "blocked_nonempty"),
                 "destination_empty": False},
            )
            raise LocalProvisioningError(
                "la carpeta de destino contiene datos y no se ha sobrescrito")
        prepared = self.state.remember_provisioning(
            plan.transaction,
            {**self._base_record(plan, "prepared"), "destination_empty": True},
        )
        return self._public(prepared)

    def apply_snapshot(self, transaction: str, payload: bytes) -> dict:
        if not _TRANSACTION.fullmatch(transaction or ""):
            raise LocalProvisioningError("identificador de transacción no válido")
        record = self.state.provisioning(transaction)
        if not record:
            raise LocalProvisioningError("transacción de provisión desconocida")
        digest = hashlib.sha256(payload).hexdigest()
        if record.get("stage") in {"data_applied", "ready", "registered"}:
            if record.get("snapshot_sha256") != digest:
                raise LocalProvisioningError(
                    "la transacción ya recibió una instantánea distinta")
            return self._public(record, repeated=True)
        if record.get("stage") not in {"prepared", "data_failed"}:
            raise LocalProvisioningError(
                "el destino no está preparado para recibir datos")
        try:
            instance = Instance.from_dict(record["instance"])
            result = self.data.apply_snapshot(
                instance,
                payload,
                self.settings.replication_token,
                self.settings.max_package_bytes,
            )
        except (ValueError, data_access.DataAccessError) as exc:
            self.state.remember_provisioning(
                transaction, {**record, "stage": "data_failed"})
            raise LocalProvisioningError(str(exc)) from exc
        applied = self.state.remember_provisioning(
            transaction,
            {
                **record,
                "stage": "data_applied",
                "snapshot_sha256": digest,
                "snapshot_created_at": result.get("created_at"),
            },
        )
        return self._public(applied)

    def activate(self, transaction: str, attempts: int = 30) -> dict:
        if not _TRANSACTION.fullmatch(transaction or ""):
            raise LocalProvisioningError("identificador de transacción no válido")
        record = self.state.provisioning(transaction)
        if not record:
            raise LocalProvisioningError("transacción de provisión desconocida")
        if record.get("stage") in {"ready", "registered"}:
            return {**self._public(record, repeated=True),
                    "instance_config": record["instance"]}
        if record.get("stage") not in {"data_applied", "health_failed"}:
            raise LocalProvisioningError(
                "el destino no tiene los datos iniciales aplicados")
        instance = Instance.from_dict(record["instance"])
        try:
            self.docker.start(instance.container)
        except docker_api.DockerError as exc:
            raise LocalProvisioningError(str(exc)) from exc
        try:
            health_origin = http_client.origin_for_host(
                self.settings.node_ip,
                instance.health_port,
                # Vaultwarden health carries no credential. Keep this internal probe
                # separate from the TLS policy for Guardian peers and floating-ip.
                allow_http=True,
                label="node_ip",
            )
        except http_client.HttpClientError as exc:
            raise LocalProvisioningError(str(exc)) from exc
        healthy = False
        detail = "sin respuesta"
        bounded_attempts = max(1, min(attempts, 60))
        for attempt in range(bounded_attempts):
            try:
                response = http_client.request(
                    health_origin,
                    instance.health_path,
                    timeout=3,
                    max_bytes=64 * 1024,
                    allow_http=True,
                )
                healthy = True
                detail = f"HTTP {response.status}"
            except http_client.HttpClientError as exc:
                detail = type(exc).__name__
            if healthy:
                break
            if attempt + 1 < bounded_attempts:
                time.sleep(1)
        if not healthy:
            try:
                self.docker.stop(instance.container)
            except docker_api.DockerError:
                pass
            self.state.remember_provisioning(
                transaction,
                {**record, "stage": "health_failed",
                 "health": {"ok": False, "detail": detail}},
            )
            raise LocalProvisioningError(
                "el Vaultwarden creado no superó la comprobación de salud")
        ready = self.state.remember_provisioning(
            transaction,
            {**record, "stage": "ready",
             "health": {"ok": True, "detail": detail}},
        )
        return {**self._public(ready), "instance_config": ready["instance"]}

    def mark_registered(self, transaction: str) -> dict:
        record = self.state.provisioning(transaction)
        if not record or record.get("stage") not in {"ready", "registered"}:
            raise LocalProvisioningError(
                "el destino no está listo para registrarse")
        registered = self.state.remember_provisioning(
            transaction, {**record, "stage": "registered"})
        return self._public(registered, repeated=record.get("stage") == "registered")

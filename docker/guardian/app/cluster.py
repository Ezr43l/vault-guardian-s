"""Lectura agregada del clúster sin convertir ausencia en éxito."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import http_client


def _read_peer(
    name: str,
    base_url: str,
    replication_token: str | None = None,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> dict:
    headers = {"Accept": "application/json"}
    if replication_token:
        headers["X-Replication-Token"] = replication_token
    try:
        response = http_client.request(
            base_url,
            "/api/v1/status",
            headers=headers,
            timeout=3,
            max_bytes=1024 * 1024,
            allow_http=allow_insecure_http,
            ca_file=ca_file,
        )
        payload = json.loads(response.body.decode("utf-8"))
    except (http_client.HttpClientError, ValueError, UnicodeDecodeError) as exc:
        return {
            "name": name,
            "reachable": False,
            "error": type(exc).__name__,
        }
    if not isinstance(payload, dict):
        return {"name": name, "reachable": False, "error": "invalid_response"}
    return {
        "name": name,
        "reachable": True,
        "status": payload,
    }


def collect_cluster(
    local_status: dict,
    peers: dict[str, str],
    replication_token: str | None = None,
    allow_insecure_http: bool = False,
    ca_file: str | None = None,
) -> dict:
    nodes = [{
        "name": local_status.get("nodo"),
        "reachable": True,
        "local": True,
        "status": local_status,
    }]
    if peers:
        with ThreadPoolExecutor(max_workers=min(len(peers), 16)) as executor:
            futures = {
                executor.submit(
                    _read_peer, name, url, replication_token,
                    allow_insecure_http, ca_file,
                ): name
                for name, url in peers.items()
            }
            for future in as_completed(futures):
                nodes.append(future.result())
    nodes.sort(key=lambda item: (not item.get("local", False), str(item.get("name"))))

    expected = 1 + len(peers)
    reachable = sum(1 for item in nodes if item.get("reachable"))
    instance_ids = sorted({
        instance.get("id")
        for node in nodes if node.get("reachable")
        for instance in (node.get("status", {}).get("instancias") or [])
        if instance.get("id")
    })
    instances = []
    severities = []
    for instance_id in instance_ids:
        fingerprints = {}
        porters = set()
        floating_known = True
        for node in nodes:
            if not node.get("reachable"):
                continue
            item = next((
                candidate for candidate in node["status"].get("instancias", [])
                if candidate.get("id") == instance_id
            ), None)
            if not item:
                continue
            content = item.get("contenido") or {}
            fingerprint = content.get("fingerprint")
            if fingerprint:
                fingerprints[str(node.get("name"))] = fingerprint
            floating = item.get("floating_ip") or {}
            floating_known = floating_known and bool(floating.get("conocido"))
            if floating.get("portador"):
                porters.add(floating["portador"])

        unique = set(fingerprints.values())
        if len(unique) > 1:
            state = "conflict"
        elif not floating_known or len(porters) != 1 or not fingerprints:
            state = "unknown"
        elif expected < 2:
            state = "degraded"
        elif reachable < expected or len(fingerprints) < expected:
            state = "degraded"
        else:
            state = "protected"
        severities.append(state)
        instances.append({
            "id": instance_id,
            "state": state,
            "porter": next(iter(porters)) if len(porters) == 1 else None,
            "fingerprints": fingerprints,
            "confirmed_nodes": len(fingerprints),
            "expected_nodes": expected,
        })

    if "conflict" in severities:
        overall = "conflict"
    elif "unknown" in severities:
        overall = "unknown"
    elif reachable < expected or "degraded" in severities:
        overall = "degraded"
    elif instances:
        overall = "protected"
    else:
        overall = "unconfigured"
    policies = [
        node.get("status", {}).get("politica")
        for node in nodes if node.get("reachable")
    ]
    policy_fingerprints = {
        json.dumps(policy, sort_keys=True, separators=(",", ":"))
        for policy in policies if isinstance(policy, dict)
    }
    return {
        "state": overall,
        "reachable_nodes": reachable,
        "expected_nodes": expected,
        "nodes": nodes,
        "instances": instances,
        "policy": local_status.get("politica") or {},
        "policy_consistent": (
            reachable == expected
            and len(policies) == expected
            and len(policy_fingerprints) == 1
        ),
    }

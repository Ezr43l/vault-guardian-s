"""Decisión conservadora para que un nodo pueda servir como portador."""

from __future__ import annotations

import datetime as dt


def _age_seconds(value: str | None, now: dt.datetime) -> float | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0.0, (now - parsed).total_seconds())


def evaluate(
    local_node: str,
    item: dict,
    cluster: dict,
    container_running: bool,
    interval_seconds: int,
    now: dt.datetime | None = None,
) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    content = item.get("contenido") or {}
    floating = item.get("floating_ip") or {}
    fingerprint = content.get("fingerprint")
    confirmed = content.get("confirmed_fingerprint")
    porter = floating.get("portador")
    role = "porter" if porter == local_node else "candidate"
    instance = next((
        value for value in cluster.get("instances", [])
        if value.get("id") == item.get("id")
    ), {})
    cluster_state = instance.get("state") or cluster.get("state") or "unknown"
    reasons = []

    if not container_running:
        reasons.append("container_not_running")
    if not floating.get("conocido") or not porter:
        reasons.append("floating_state_unknown")
    if cluster_state == "conflict":
        reasons.append("replication_conflict")

    if role == "porter":
        if floating.get("salud_local") is not True:
            reasons.append("local_health_not_confirmed")
    else:
        if not fingerprint:
            reasons.append("missing_fingerprint")
        if not confirmed or confirmed != fingerprint:
            reasons.append("fingerprint_not_confirmed")
        fingerprints = instance.get("fingerprints") or {}
        porter_fingerprint = fingerprints.get(porter)
        if porter_fingerprint:
            if fingerprint != porter_fingerprint:
                reasons.append("behind_current_porter")
        else:
            reachable = set(fingerprints.values())
            if reachable and reachable != {fingerprint}:
                reasons.append("reachable_nodes_diverge")
            age = _age_seconds(content.get("updated_at"), now)
            freshness_limit = max(60, interval_seconds * 2)
            if age is None or age > freshness_limit:
                reasons.append("replica_too_old_for_failover")

    return {
        "ready": not reasons,
        "instance": item.get("id"),
        "node": local_node,
        "role": role,
        "porter": porter,
        "cluster_state": cluster_state,
        "fingerprint": fingerprint,
        "reasons": reasons,
    }

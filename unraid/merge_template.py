#!/usr/bin/env python3
"""Fusiona la plantilla compartible con los valores elegidos por el usuario."""

from __future__ import annotations

import argparse
import os
import xml.etree.ElementTree as ET
from pathlib import Path


RUNTIME_TARGETS = {
    "VG_NODE",
    "VG_NODE_IP",
    "VG_PEERS",
    "VG_FLOATING_API",
    "VG_MODE",
    "VG_INTERVAL_SECONDS",
    "VG_BACKUP_RETENTION",
    "VG_MAX_PACKAGE_MB",
}


def configs(root: ET.Element) -> list[ET.Element]:
    return list(root.findall("Config"))


def by_target(root: ET.Element, target: str) -> ET.Element | None:
    return next(
        (item for item in configs(root) if item.attrib.get("Target") == target),
        None,
    )


def preserve_value(destination: ET.Element, existing: ET.Element | None) -> None:
    if existing is None:
        return
    destination.text = existing.text
    if existing.attrib.get("Default"):
        destination.set("Default", existing.attrib["Default"])


def merge(source: Path, existing: Path | None) -> ET.Element:
    target_root = ET.parse(source).getroot()
    existing_root = (
        ET.parse(existing).getroot()
        if existing is not None and existing.is_file() and existing.stat().st_size
        else None
    )
    if existing_root is None:
        return target_root

    for target in (
        "6062",
        "/state",
        "/instances",
        "/var/run/docker.sock",
    ):
        preserve_value(by_target(target_root, target), by_target(existing_root, target))

    for item in list(configs(target_root)):
        if item.attrib.get("Target") in RUNTIME_TARGETS:
            target_root.remove(item)
    return target_root


def apply_deployment_values(root: ET.Element) -> None:
    """Aplica al XML instalado los valores usados por el despliegue."""

    environment = {
        "/state": "VG_TEMPLATE_STATE_PATH",
        "/instances": "VG_TEMPLATE_DATA_PATH",
    }
    for target, variable in environment.items():
        value = os.getenv(variable, "")
        item = by_target(root, target)
        if item is not None and value:
            item.text = value


def write_private_template(root: ET.Element, output: Path) -> None:
    ET.indent(root, space="  ")
    output.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(
        output,
        encoding="utf-8",
        xml_declaration=True,
        short_empty_elements=True,
    )
    os.chmod(output, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--existing", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--webui", required=True)
    parser.add_argument("--icon", required=True)
    parser.add_argument("--port", required=True)
    args = parser.parse_args()

    root = merge(args.source, args.existing)
    apply_deployment_values(root)
    root.find("Repository").text = args.repository
    root.find("WebUI").text = args.webui
    root.find("Icon").text = args.icon
    port = by_target(root, "6062")
    port.text = args.port
    port.set("Default", args.port)
    write_private_template(root, args.output)

if __name__ == "__main__":
    main()

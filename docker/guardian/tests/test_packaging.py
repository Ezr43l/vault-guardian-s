"""Comprobaciones de empaquetado compartible y recursos de Unraid."""

from __future__ import annotations

import struct
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / "unraid" / "my-Vault-Guardian.xml"
VERSION_FILE = ROOT / "VERSION"
WEB = ROOT / "docker" / "guardian" / "web"


class PackagingTests(unittest.TestCase):
    def test_template_publishes_the_panel_port(self) -> None:
        root = ET.parse(TEMPLATE).getroot()
        ports = [
            item for item in root.findall("Config")
            if item.attrib.get("Type") == "Port" and item.attrib.get("Target") == "6062"
        ]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0].attrib.get("Mode"), "tcp")
        self.assertIn("[PORT:6062]", root.findtext("WebUI", ""))

    def test_template_uses_a_public_icon_before_container_start(self) -> None:
        root = ET.parse(TEMPLATE).getroot()
        self.assertEqual(
            root.findtext("Icon"),
            "https://raw.githubusercontent.com/Ezr43l/vault-guardian-s/main/docker/guardian/web/icono.png",
        )
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        self.assertIn('href="/favicon.png"', page)

    def test_shared_template_tracks_the_project_version(self) -> None:
        root = ET.parse(TEMPLATE).getroot()
        version = VERSION_FILE.read_text(encoding="utf-8").strip()
        self.assertEqual(
            root.findtext("Repository"),
            f"ghcr.io/ezr43l/vault-guardian-s:{version}",
        )
        self.assertFalse(
            (ROOT / "unraid" / "my-Vault-Guardian-Docker-Control.xml").exists()
        )

    def test_icons_are_real_rgba_png_files(self) -> None:
        expected = {
            "icon-512.png": (512, 512),
            "icono.png": (128, 128),
            "favicon.png": (64, 64),
        }
        for filename, dimensions in expected.items():
            payload = (WEB / filename).read_bytes()
            self.assertEqual(payload[:8], b"\x89PNG\r\n\x1a\n")
            width, height = struct.unpack(">II", payload[16:24])
            self.assertEqual((width, height), dimensions)
            self.assertEqual(payload[25], 6, f"{filename} debe conservar canal alfa")

    def test_template_only_asks_for_bootstrap_values(self) -> None:
        root = ET.parse(TEMPLATE).getroot()
        items = root.findall("Config")
        visible = [item for item in items if item.attrib.get("Display") == "always"]
        advanced = [item for item in items if item.attrib.get("Display") == "advanced"]
        self.assertEqual(len(items), 4)
        self.assertEqual(len(visible), 4)
        self.assertEqual(len(advanced), 0)
        self.assertEqual(
            {item.attrib.get("Target") for item in visible},
            {
                "6062",
                "/state",
                "/instances",
                "/var/run/docker.sock",
            },
        )
        forbidden_runtime = {
            "VG_NODE", "VG_NODE_IP", "VG_PEERS", "VG_FLOATING_API", "VG_MODE",
            "VG_INTERVAL_SECONDS", "VG_BACKUP_RETENTION", "VG_MAX_PACKAGE_MB",
        }
        self.assertTrue(forbidden_runtime.isdisjoint(
            item.attrib.get("Target") for item in items
        ))
        self.assertTrue(all(item.attrib.get("Description") for item in items))

    def test_single_template_mounts_docker_socket_once(self) -> None:
        portal = TEMPLATE.read_text(encoding="utf-8")
        self.assertEqual(portal.count('Target="/var/run/docker.sock"'), 1)
        self.assertNotIn("VG_DOCKER_SOCKET", portal)
        self.assertNotIn("VG_DOCKER_ENDPOINT", portal)
        self.assertNotIn("VG_DOCKER_CONTROL_TOKEN_FILE", portal)

    def test_template_keeps_human_credentials_in_the_portal(self) -> None:
        root = ET.parse(TEMPLATE).getroot()
        by_target = {
            item.attrib.get("Target"): item for item in root.findall("Config")
        }
        self.assertNotIn("VG_ADMIN_USER", by_target)
        self.assertNotIn("VG_ADMIN_PASSWORD", by_target)
        for direct_secret in (
            "VG_REPLICATION_TOKEN", "VG_FLOATING_API_TOKEN", "VG_API_TOKEN"
        ):
            self.assertNotIn(direct_secret, by_target)
        self.assertFalse(any("secret" in target.lower() or "token" in target.lower()
                             for target in by_target if target))
        overview = root.findtext("Overview", "").lower()
        self.assertIn("alta inicial", overview)
        self.assertIn("no incluye datos", overview)

if __name__ == "__main__":
    unittest.main()

import importlib.util
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "unraid" / "my-Vault-Guardian.xml"
MODULE_PATH = ROOT / "unraid" / "merge_template.py"
SPEC = importlib.util.spec_from_file_location("merge_template", MODULE_PATH)
MERGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGER)


class TemplateMergeTests(unittest.TestCase):
    def test_merge_only_preserves_docker_bootstrap_values(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing.xml"
            root = ET.parse(SOURCE).getroot()
            by_target = {
                item.attrib.get("Target"): item for item in root.findall("Config")
            }
            by_target["6062"].text = "16062"
            by_target["/state"].text = "/host/vault-guardian"
            by_target["/instances"].text = "/host/appdata"
            ET.SubElement(root, "Config", {
                "Name": "Nombre privado antiguo",
                "Target": "VG_NODE",
                "Type": "Variable",
            }).text = "private-node"
            ET.SubElement(root, "Config", {
                "Name": "Acceso HTTP antiguo",
                "Target": "VG_ALLOW_INSECURE_PORTAL",
                "Type": "Variable",
            }).text = "true"
            ET.ElementTree(root).write(
                existing, encoding="utf-8", xml_declaration=True)

            merged = MERGER.merge(SOURCE, existing)
            values = {
                item.attrib.get("Target"): item.text
                for item in merged.findall("Config")
            }
            self.assertEqual(set(values), {
                "6062", "/state", "/instances", "/var/run/docker.sock",
            })
            self.assertEqual(values["6062"], "16062")
            self.assertEqual(values["/state"], "/host/vault-guardian")
            self.assertEqual(values["/instances"], "/host/appdata")
            self.assertNotIn("VG_NODE", values)
            self.assertNotIn("VG_ALLOW_INSECURE_PORTAL", values)

    def test_deployment_can_override_state_without_embedding_secrets(self):
        root = MERGER.merge(SOURCE, None)
        with mock.patch.dict(os.environ, {
            "VG_TEMPLATE_STATE_PATH": "/host/state",
            "VG_TEMPLATE_DATA_PATH": "/host/appdata",
        }, clear=False):
            MERGER.apply_deployment_values(root)
        values = {
            item.attrib.get("Target"): item.text
            for item in root.findall("Config")
        }
        self.assertEqual(values["/state"], "/host/state")
        self.assertEqual(values["/instances"], "/host/appdata")
        serialized = ET.tostring(root, encoding="unicode")
        self.assertNotIn("replication-token", serialized)
        self.assertNotIn("floating-api-token", serialized)


if __name__ == "__main__":
    unittest.main()

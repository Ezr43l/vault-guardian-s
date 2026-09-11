import unittest

import provisioning


def inspected(**overrides):
    payload = {
        "Name": "/Vaultwarden",
        "Path": "/start.sh",
        "Args": [],
        "Image": "sha256:" + "a" * 64,
        "Config": {
            "Image": "vaultwarden/server:latest",
            "Env": [
                "PATH=/usr/local/bin",
                "HOST_HOSTNAME=node-1",
                "ADMIN_TOKEN=secret",
                "SIGNUPS_ALLOWED=false",
                "TZ=Europe/Madrid",
            ],
        },
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "bridge",
            "CapAdd": None,
            "Devices": [],
            "PortBindings": {
                "80/tcp": [{"HostIp": "", "HostPort": "5743"}],
            },
        },
        "Mounts": [{
            "Type": "bind",
            "Source": "/mnt/user/appdata/vaultwarden",
            "Destination": "/data",
            "RW": True,
        }],
        "State": {"Running": True},
    }
    payload.update(overrides)
    return payload


def image():
    return {
        "RepoDigests": [
            "vaultwarden/server@sha256:" + "b" * 64,
        ],
    }


class ProvisioningTests(unittest.TestCase):
    def test_normalizes_realistic_vaultwarden_without_exposing_values(self):
        spec = provisioning.normalize(inspected(), image())
        public = spec.public()

        self.assertEqual("Vaultwarden", spec.container)
        self.assertEqual(5743, spec.host_port)
        self.assertEqual("/mnt/user/appdata/vaultwarden", spec.data_source)
        self.assertEqual(
            "vaultwarden/server@sha256:" + "b" * 64,
            spec.pinned_image,
        )
        self.assertIn("ADMIN_TOKEN", public["environment_keys"])
        self.assertNotIn("PATH", public["environment_keys"])
        self.assertNotIn("HOST_HOSTNAME", public["environment_keys"])
        self.assertNotIn("secret", str(public))
        self.assertFalse(public["environment_values_exposed"])

    def test_rejects_host_network_and_privileged_containers(self):
        host_network = inspected()
        host_network["HostConfig"]["NetworkMode"] = "host"
        with self.assertRaisesRegex(provisioning.ProvisioningError, "bridge"):
            provisioning.normalize(host_network, image())

        privileged = inspected()
        privileged["HostConfig"]["Privileged"] = True
        with self.assertRaisesRegex(provisioning.ProvisioningError, "privilegiado"):
            provisioning.normalize(privileged, image())

    def test_rejects_extra_mounts_ports_devices_and_custom_start(self):
        extra_mount = inspected()
        extra_mount["Mounts"].append({
            "Type": "bind",
            "Source": "/etc",
            "Destination": "/host",
            "RW": False,
        })
        with self.assertRaisesRegex(provisioning.ProvisioningError, "montajes extra"):
            provisioning.normalize(extra_mount, image())

        extra_port = inspected()
        extra_port["HostConfig"]["PortBindings"]["443/tcp"] = [{
            "HostIp": "", "HostPort": "5443",
        }]
        with self.assertRaisesRegex(provisioning.ProvisioningError, "puertos adicionales"):
            provisioning.normalize(extra_port, image())

        devices = inspected()
        devices["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/sda"}]
        with self.assertRaisesRegex(provisioning.ProvisioningError, "dispositivos"):
            provisioning.normalize(devices, image())

        custom = inspected(Path="/bin/sh", Args=["-c", "something"])
        with self.assertRaisesRegex(provisioning.ProvisioningError, "personalizado"):
            provisioning.normalize(custom, image())

        custom_user = inspected()
        custom_user["Config"]["User"] = "99:100"
        with self.assertRaisesRegex(
            provisioning.ProvisioningError, "usuario personalizado"
        ):
            provisioning.normalize(custom_user, image())

        explicit_root = inspected()
        explicit_root["Config"]["User"] = "0:0"
        self.assertEqual(
            "Vaultwarden", provisioning.normalize(explicit_root, image()).container
        )

    def test_rejects_unpinned_or_non_official_image(self):
        with self.assertRaisesRegex(provisioning.ProvisioningError, "digest"):
            provisioning.normalize(inspected(), {"RepoDigests": []})

        other = inspected()
        other["Config"]["Image"] = "example/vaultwarden:latest"
        result = provisioning.candidate(other, image())
        self.assertFalse(result["vaultwarden"])

    def test_candidate_explains_why_an_official_container_is_not_eligible(self):
        bad = inspected()
        bad["HostConfig"]["NetworkMode"] = "host"
        result = provisioning.candidate(bad, image())

        self.assertTrue(result["vaultwarden"])
        self.assertFalse(result["eligible"])
        self.assertIn("bridge", result["blockers"][0])

    def test_private_spec_round_trip_builds_a_bounded_container(self):
        source = provisioning.normalize(inspected(), image())
        restored = provisioning.VaultwardenSpec.from_private(source.private())
        target = provisioning.target_data_path(
            "/mnt/user/appdata", "vaultwarden-1")
        spec = provisioning.container_create_spec(
            restored,
            transaction="provision:12345678",
            target_path=target,
        )

        self.assertEqual(source.pinned_image, spec["Image"])
        self.assertIn("ADMIN_TOKEN=secret", spec["Env"])
        self.assertEqual(
            ["/mnt/user/appdata/vaultwarden-1:/data:rw"],
            spec["HostConfig"]["Binds"],
        )
        self.assertEqual("bridge", spec["HostConfig"]["NetworkMode"])
        self.assertFalse(spec["HostConfig"]["Privileged"])
        self.assertEqual([], spec["HostConfig"]["CapAdd"])
        self.assertEqual([], spec["HostConfig"]["Devices"])
        self.assertNotIn("/var/run/docker.sock", str(spec))
        self.assertNotIn("Entrypoint", spec)
        self.assertNotIn("Cmd", spec)

    def test_target_path_and_private_spec_reject_unsafe_input(self):
        for root in ("", "/", "/tmp/..", "relative/path"):
            with self.subTest(root=root):
                with self.assertRaises(provisioning.ProvisioningError):
                    provisioning.target_data_path(root, "vaultwarden-1")
        with self.assertRaises(provisioning.ProvisioningError):
            provisioning.target_data_path(
                "/mnt/user/appdata", "../another-service")

        self.assertEqual(
            "/mnt/cache/appdata/vaultwarden-3",
            provisioning.exact_target_data_path(
                "/mnt/cache/appdata/vaultwarden-3"),
        )
        for target in ("", "/", "relative/path", "/mnt/appdata/../etc"):
            with self.subTest(target=target):
                with self.assertRaises(provisioning.ProvisioningError):
                    provisioning.exact_target_data_path(target)

        private = provisioning.normalize(inspected(), image()).private()
        private["pinned_image"] = "example.invalid/vaultwarden@sha256:" + "a" * 64
        with self.assertRaisesRegex(
            provisioning.ProvisioningError, "digest oficial"
        ):
            provisioning.VaultwardenSpec.from_private(private)


if __name__ == "__main__":
    unittest.main()

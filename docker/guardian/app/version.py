"""Versión que se muestra en la API y el panel."""

import os


VERSION = os.environ.get("VG_VERSION", "dev")

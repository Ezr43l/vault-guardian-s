import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "docker" / "guardian" / "web"


class IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.section_depth = 0
        self.footer_depth = 0
        self.invalid_nesting = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "section":
            if self.section_depth or self.footer_depth:
                self.invalid_nesting.append("section")
            self.section_depth += 1
        elif tag == "footer":
            if self.section_depth or self.footer_depth:
                self.invalid_nesting.append("footer")
            self.footer_depth += 1

    def handle_endtag(self, tag):
        if tag == "section":
            self.section_depth -= 1
        elif tag == "footer":
            self.footer_depth -= 1


class UiTests(unittest.TestCase):
    def test_login_application_and_operational_sections_exist(self):
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        parser = IdCollector()
        parser.feed(page)
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for identifier in (
            "login-page",
            "login-form",
            "login-username",
            "login-password",
            "setup-display-name",
            "setup-confirm-password",
            "setup-cluster-token",
            "setup-portal-access",
            "login-factor",
            "app-shell",
            "account-button",
            "disconnect",
            "overview",
            "setup-panel",
            "instances-panel",
            "refresh-instances",
            "cluster-servers-panel",
            "cluster-services-panel",
            "history-panel",
            "history-pagination",
            "recovery-panel",
            "security-panel",
            "profile-form",
            "users-list",
            "two-factor-setup",
            "setup-checks-wrap",
            "policy-settings",
            "keepalived-integration-form",
            "keepalived-integration-token",
            "application-settings-form",
            "application-session",
            "application-history-size",
            "application-history-entries",
            "api-integration-form",
            "api-integration-list",
            "api-integration-name",
            "api-integration-token",
            "api-token-result",
            "copy-api-token",
            "private-ca-form",
            "private-ca-pem",
            "show-enrollment-token",
            "enrollment-token",
            "cluster-builder-wrap",
            "provision-form-wrap",
            "app-dialog",
            "codes-dialog",
        ):
            self.assertIn(identifier, parser.ids)
        self.assertEqual(parser.invalid_nesting, [])
        self.assertEqual(parser.section_depth, 0)
        self.assertEqual(parser.footer_depth, 0)

    def test_ui_uses_five_focused_product_views(self):
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        for view in (
            "inicio", "configuracion", "instancias",
            "operacion", "seguridad",
        ):
            self.assertIn(f'data-view-panel="{view}"', page)
            self.assertIn(f'data-view="{view}"', page)
        self.assertIn("Resumen", page)
        self.assertIn("Grupo", page)
        self.assertIn("Vaultwarden", page)
        self.assertIn("Operación", page)
        self.assertIn("Seguridad", page)
        self.assertNotIn('data-view="ayuda"', page)
        self.assertNotIn('data-view-panel="ayuda"', page)
        self.assertNotIn(">Referencia<", page)

    def test_login_sessions_users_and_totp_are_real_api_flows(self):
        script = (WEB / "app.js").read_text(encoding="utf-8")
        for route in (
            "/api/v1/auth/status",
            "/api/v1/auth/setup",
            "/api/v1/session",
            "/api/v1/users",
            "/api/v1/profile",
            "/api/v1/profile/2fa/setup",
            "/api/v1/profile/2fa/confirm",
            "/api/v1/profile/2fa/disable",
            "/api/v1/profile/recovery-codes",
        ):
            self.assertIn(route, script)
        self.assertIn("X-CSRF-Token", script)
        self.assertIn("TWO_FACTOR_REQUIRED", script)
        self.assertIn("recovery_codes", script)
        self.assertIn("Crear primera cuenta", script)
        self.assertIn("result.identidades", script)
        self.assertIn("Identidades pendientes en", script)
        self.assertIn("password_confirmation", script)
        self.assertNotIn("adminToken", script)
        self.assertNotIn("Desbloquear", script)

    def test_operational_endpoints_and_automatic_provisioning_remain(self):
        script = (WEB / "app.js").read_text(encoding="utf-8")
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        for route in (
            "/api/v1/cluster",
            "/api/v1/history?limit=50",
            "/api/v1/cluster/policy",
            "/api/v1/cluster/configuration",
            "/api/v1/cluster/enrollment-token",
            "/api/v1/integrations/keepalived",
            "/api/v1/application-settings",
            "/api/v1/integrations/applications",
            "/api/v1/tls/private-ca",
            "/api/v1/provisioning/candidates",
            "/api/v1/provisioning",
            "/api/v1/reconciliation",
            "/api/v1/provisioning/transactions/",
            "/sync",
            "/readiness",
        ):
            self.assertIn(route, script)
        self.assertIn("'Idempotency-Key': provisionTransaction", script)
        self.assertIn("window.sessionStorage", script)
        self.assertIn("Sincronización iniciada", script)
        self.assertIn("Finalizada · ", script)
        self.assertIn("destination_paths", script)
        self.assertIn("provision-destination-fields", page)
        self.assertNotIn("Raíz de réplicas pendiente", script)
        self.assertNotIn("member-vaultwarden-root", script)
        self.assertIn("Permitir conexiones HTTP en la red interna", page)
        self.assertIn("class=\"check-row cluster-http-option\"", page)

    def test_all_static_id_selectors_exist_in_the_document(self):
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        script = (WEB / "app.js").read_text(encoding="utf-8")
        identifiers = set(re.findall(r'id="([^"]+)"', page))
        selected = set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", script))
        self.assertEqual(set(), selected - identifiers)

    def test_api_errors_are_not_inserted_as_html(self):
        script = (WEB / "app.js").read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"innerHTML\s*=.*error\.message", script))
        self.assertIn("message.textContent =", script)

    def test_browser_native_confirmation_and_secret_unlock_are_absent(self):
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        script = (WEB / "app.js").read_text(encoding="utf-8")
        combined = (page + "\n" + script).lower()
        self.assertIn("function confirmarenpanel", combined)
        self.assertNotIn("window.confirm", script)
        self.assertNotIn("window.alert", script)
        self.assertNotIn("contraseña maestra", combined)
        self.assertNotIn("contraseña de administración", combined)
        self.assertNotIn("desbloque", combined)
        self.assertNotIn("sólo lectura", combined)
        self.assertNotIn("solo lectura", combined)

    def test_common_guardian_visual_language_is_present(self):
        css = (WEB / "panel.css").read_text(encoding="utf-8")
        for rule in (
            "--fondo: #0e1418",
            "--panel: #161e23",
            "--acento: #22d3ee",
            ".login-page",
            ".login-intro",
            ".app-header",
            ".app-nav",
            ".page-heading",
            ".dialogo",
            ".security-grid",
            ".dashboard-grid",
            ".service-card",
        ):
            self.assertIn(rule, css)
        self.assertEqual(css.count("{"), css.count("}"))

    def test_status_cards_keep_names_and_details_visually_separate(self):
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        script = (WEB / "app.js").read_text(encoding="utf-8")
        css = (WEB / "panel.css").read_text(encoding="utf-8")
        self.assertIn("mobile-account-label", page)
        for hook in (
            "member-status-icon",
            "member-status-copy",
            "member-status-name",
            "member-status-detail",
            "cluster-item-title",
            "cluster-item-detail",
        ):
            self.assertIn(hook, script)
            self.assertIn(hook, css)
        self.assertIn("#current-user { display: none; }", css)
        self.assertIn(".user-row { grid-template-columns: 1fr;", css)

    def test_information_architecture_is_compact_stable_and_paginated(self):
        page = (WEB / "panel.html").read_text(encoding="utf-8")
        script = (WEB / "app.js").read_text(encoding="utf-8")
        css = (WEB / "panel.css").read_text(encoding="utf-8")
        self.assertIn('id="cluster-servers"', page)
        self.assertIn('id="cluster-services"', page)
        self.assertIn('id="history-pagination"', page)
        self.assertIn('id="setup-checks-wrap"', page)
        self.assertIn('id="policy-settings"', page)
        self.assertIn('class="instance-list"', page)
        self.assertIn("const HISTORY_PAGE_SIZE = 10", script)
        self.assertIn("historyItems.slice(start, start + HISTORY_PAGE_SIZE)", script)
        self.assertIn("activeView === 'instancias'", script)
        self.assertIn("skipInstances: skipInstances", script)
        self.assertIn("refresh({periodic: true})", script)
        self.assertIn("member-row-summary", script)
        self.assertIn("service-facts", script)
        self.assertIn(".pagination", css)
        self.assertNotIn("Ver detalles técnicos", page + script)
        self.assertNotIn("instance-facts", script)
        self.assertNotIn("instance-card", script)

    def test_copy_is_direct_and_avoids_internal_editorial_labels(self):
        production = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in WEB.glob("*")
            if path.suffix in {".html", ".js", ".css"}
        ).lower()
        for forbidden in ("guía sin jerga", "tus vaultwarden"):
            self.assertIsNone(re.search(rf"\b{re.escape(forbidden)}\b", production))


if __name__ == "__main__":
    unittest.main()

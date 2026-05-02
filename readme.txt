=== RichardMedina Security Hardening ===
Contributors: richardmedina
Tags: security, firewall, hardening, injection, xss
Requires at least: 6.4
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 0.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hardens WordPress against injection attempts and common attack vectors. Internal RichardMedina agency plugin.

== Description ==

A focused security plugin for sites we host. Two pillars in v0.1:

* **Request firewall** — inspects $_GET, $_POST, cookies, and selected headers for SQLi, XSS, LFI/RFI, and known web-shell patterns. Modes: off, monitor (log only), block (HTTP 403).
* **Hardening toggles** — disable XML-RPC, block PHP execution in uploads/, block ?author= user enumeration, hide REST users endpoint for unauthenticated requests, remove generator meta, optional disable application passwords.

Single-site only in v0.1. Deliberately does **not** scan or clean files — that is planned for a later milestone, behind a quarantine-only-by-default model.

== Installation ==

1. Upload the `richardmedina-security-hardening` folder to `wp-content/plugins/`.
2. Activate via Plugins → Installed Plugins.
3. Visit Settings → RM Hardening.
4. Run for at least 24 hours in **Monitor** mode before flipping the firewall to **Block**.

== Changelog ==

= 0.1.1 =
Security: stop trusting X-Forwarded-For / CF-Connecting-IP by default in the firewall's IP detection. New `firewall_trust_proxy` toggle (off by default) re-enables forwarded headers for sites genuinely behind a proxy.
Hardening: cap-deny toggles for installing/uploading plugins, the in-admin plugin file editor, and core updates.
Hardening: restrict REST API to same-origin / local requests, with an IP/CIDR allowlist for trusted services (BlogVault, ManageWP, Jetpack workers).
Admin: redesigned settings UI — branded header strip, status-overview cards, CSS toggle switches, grouped Hardening sections, copy-to-clipboard diagnostics, Settings action link on the Plugins screen.

= 0.1.0 =
* Initial release: request firewall + hardening toggles.

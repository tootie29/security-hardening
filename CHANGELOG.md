# Changelog

## 0.1.1 — 2026-05-03

### Security
- **H1 fix:** firewall's `client_ip()` no longer consults `X-Forwarded-For` / `CF-Connecting-IP` by default. On any non-proxied site those headers are attacker-controlled, so trusting them let an attacker spoof an IP into `firewall_ip_allowlist` and bypass `block` mode entirely. Default behavior is now `REMOTE_ADDR`-only. New `firewall_trust_proxy` toggle (off by default, surfaced at the bottom of the Firewall tab) re-enables the forwarded-header path for sites genuinely behind a proxy under the operator's control.

### Hardening
- Three new opt-in cap-deny toggles: disable installing / uploading plugins (`install_plugins`, `upload_plugins`), disable the in-admin plugin file editor (`edit_plugins`), disable core updates (`update_core`). Implemented via `map_meta_cap` returning `do_not_allow` so it works without `DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS` in `wp-config.php`.
- New "Restrict REST API to same-origin / local requests" toggle that gates `rest_authentication_errors` based on `Origin` / `Referer` matching `home_url()` host (header-less loopback also allowed for cron / server-to-server).
- IP / CIDR allowlist on the REST restriction so legitimate services (BlogVault migration, ManageWP, Jetpack) keep working when the toggle is on. Supports IPv4, IPv6, and CIDR notation; matches against `REMOTE_ADDR`.

### Admin UX
- Redesigned settings UI: branded header strip with shield mark + status badges, status-overview card grid (toggles enabled, firewall mode pill, last firewall match, log file size), CSS-only toggle switches replacing checkboxes, grouped Hardening sections (Surface reduction / Access control / Admin lockdown / API access), inline descriptions on nuanced toggles.
- Copy-to-clipboard button on the Diagnostics tab (vanilla JS, no jQuery dependency).
- "Settings" action link added to the plugin row on `/wp-admin/plugins.php`.
- Diagnostics report now includes more environment context.

## 0.1.0 — 2026-05-02

Initial release.

- Request firewall (off / monitor / block) covering SQLi, XSS, LFI/RFI, and known web-shell signatures.
- Hardening toggles: disable XML-RPC, block PHP execution in `uploads/` via `.htaccess`, block `?author=` user enumeration, hide `/wp/v2/users` for unauthenticated requests, remove generator meta, DISALLOW_FILE_EDIT advisory notice, optional disable of application passwords, disable installing/uploading new plugins (`install_plugins`, `upload_plugins`), disable the in-admin plugin file editor (`edit_plugins`), disable WordPress core updates (`update_core`).
- Settings page under **Settings → RM Hardening** with Status, Firewall, Hardening, Diagnostics tabs.
- File-based logger in `uploads/rm-sh-logs/` (htaccess-protected). Block events always logged; other events require Debug mode.
- Diagnostics action with copy-paste-ready report.
- Single-site only; activation refused on multisite.

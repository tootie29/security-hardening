# Changelog

## 0.1.0 — 2026-05-02

Initial release.

- Request firewall (off / monitor / block) covering SQLi, XSS, LFI/RFI, and known web-shell signatures.
- Hardening toggles: disable XML-RPC, block PHP execution in `uploads/` via `.htaccess`, block `?author=` user enumeration, hide `/wp/v2/users` for unauthenticated requests, remove generator meta, DISALLOW_FILE_EDIT advisory notice, optional disable of application passwords.
- Settings page under **Settings → RM Hardening** with Status, Firewall, Hardening, Diagnostics tabs.
- File-based logger in `uploads/rm-sh-logs/` (htaccess-protected). Block events always logged; other events require Debug mode.
- Diagnostics action with copy-paste-ready report.
- Single-site only; activation refused on multisite.

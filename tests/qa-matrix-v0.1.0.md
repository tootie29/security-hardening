# Manual QA matrix — RichardMedina Security Hardening v0.1.0

Walked through on staging before tagging the release. Record `pass` / `fail` / `n/a` and a short note. Sign and date at the bottom.

**Site under test:** `___________________________`
**WP / PHP versions:** `___________________________`
**Tester / date:** `___________________________`

## A. Lifecycle

| # | Scenario | Expected | Result | Notes |
|---|---|---|---|---|
| A1 | Fresh install on clean WP, then activate | No PHP notices/warnings/fatals. `Settings → RM Hardening` reachable. Defaults loaded (firewall=monitor, all hardening on except app passwords + file-edit notice). | | |
| A2 | Activate on multisite | Activation refused with admin notice; no fatal. | | |
| A3 | Deactivate then reactivate | Settings preserved. Log dir intact. No duplicates of anything. | | |
| A4 | Uninstall via WP UI | `rm_sh_settings`, `rm_sh_version`, `rm_sh_diag_report` transient gone. `uploads/rm-sh-logs/` removed. `# BEGIN/END RichardMedina Security Hardening` block stripped from `uploads/.htaccess`; the rest of that file untouched. | | |
| A5 | `WP_DEBUG = true`, `WP_DEBUG_LOG = true` | Zero notices/warnings in `wp-content/debug.log` from the plugin during install + browse + save. | | |

## B. Settings page

| # | Scenario | Expected | Result | Notes |
|---|---|---|---|---|
| B1 | Visit each tab (Status / Firewall / Hardening / Diagnostics) | Renders without errors. Active tab highlighted. | | |
| B2 | Toggle a setting on Firewall tab and save | Saved value persists. Hardening + Status values *also* preserved (hidden-input round-trip). | | |
| B3 | Save Hardening tab; check Firewall tab still has correct values | Untouched tab values preserved. | | |
| B4 | Click "Reset to defaults", confirm dialog | Settings revert to defaults. Success notice shown. | | |
| B5 | Submit garbage in IP allowlist textarea (e.g. `<script>alert(1)</script>`) | Sanitized via `sanitize_textarea_field` on save. | | |
| B6 | Submit invalid `firewall_mode` via tampered POST | Falls back to `monitor`. | | |
| B7 | View settings page mobile-width (devtools, 375px) | Tabs and fields usable. | | |

## C. Capabilities

| # | Scenario | Expected | Result | Notes |
|---|---|---|---|---|
| C1 | As Administrator | Full access to settings page and diagnostics action. | | |
| C2 | As Editor | `Settings → RM Hardening` not visible. Direct URL returns nothing. Diagnostics admin-post handler returns 403. | | |
| C3 | As logged-out visitor | No admin leakage. Frontend behavior normal. | | |
| C4 | Tampered nonce on diagnostics POST | Rejected by `check_admin_referer`. | | |
| C5 | Tampered nonce on reset POST | Rejected. | | |

## D. Firewall — monitor mode

Set `firewall_mode = monitor`. Use a private/incognito window so cookies don't whitelist you accidentally.

| # | Request | Expected | Result | Notes |
|---|---|---|---|---|
| D1 | `GET /?q=<script>alert(1)</script>` | 200 OK. Log line `firewall.match` with `signature=xss.script_tag`. | | |
| D2 | `GET /?id=1' UNION SELECT user_pass FROM wp_users --` | 200 OK. Log line `signature=sqli.union_select`. | | |
| D3 | `GET /?file=../../../../etc/passwd` | 200 OK. Log line `signature=lfi.traversal` or `lfi.sensitive_path`. | | |
| D4 | URL-encoded payload `?q=%3Cscript%3Ealert(1)%3C/script%3E` | Detected after rawurldecode. | | |
| D5 | Header injection: curl with `-H "Referer: javascript:alert(1)"` | 200 OK. Log line for HEADER bucket. | | |
| D6 | Normal post edit save with rich HTML in `post_content` | No false positive (param allowlist exempts `post_content`). | | |

## E. Firewall — block mode

Switch `firewall_mode = block`.

| # | Request | Expected | Result | Notes |
|---|---|---|---|---|
| E1 | Same payloads D1–D5 | HTTP 403, plain "Forbidden", no HTML. Log line `firewall.blocked`. | | |
| E2 | Add own IP to IP allowlist, retry D1 | 200 OK. No log line. | | |
| E3 | Remove IP, add `/wp-admin/` to URL allowlist, retry D1 against an admin URL | 200 OK in /wp-admin only; still blocked elsewhere. | | |
| E4 | Add `q` to parameter allowlist, retry D1 | 200 OK; no log line. | | |
| E5 | Normal admin work (saving posts, navigating) | Nothing blocked. No log spam. | | |
| E6 | WP-CLI command (e.g. `wp option get blogname`) | Skipped — no firewall interference. | | |
| E7 | wp-cron run | Skipped — no firewall interference. | | |

## F. Hardening toggles

Test each toggle on, then off, observing the side effect.

| # | Toggle | On verification | Off verification | Result |
|---|---|---|---|---|
| F1 | Disable XML-RPC | `POST /xmlrpc.php` → disabled response. `X-Pingback` header absent on frontend. | XML-RPC reachable again. | |
| F2 | Block PHP in uploads | `uploads/.htaccess` has Security Hardening block. Drop `test.php` with `<?php echo 'pwn'; ?>` into uploads, request it → 403. | Block stripped from `.htaccess`. Same request executes (or 404 if removed). | |
| F3 | Block ?author= enum | `/?author=1` → 301 redirect home. Log line `hardening.author_enum`. | `/?author=1` → standard author archive (or 404). | |
| F4 | Hide REST users | `GET /wp-json/wp/v2/users` (logged out) → 404. Logged in → returns users. | Logged out → returns users normally. | |
| F5 | Remove generator | `<meta name="generator">` absent in frontend HTML. | Tag present. | |
| F6 | DISALLOW_FILE_EDIT advisory | If wp-config doesn't define it → admin notice on every screen. | Notice gone after defining the constant. | |
| F7 | Disable application passwords | Profile screen has app passwords section hidden / `wp_is_application_passwords_available()` returns false. | Section visible again. | |

## G. Diagnostics

| # | Scenario | Expected | Result | Notes |
|---|---|---|---|---|
| G1 | Click "Run diagnostics" | Redirects back to Diagnostics tab with a populated textarea. | | |
| G2 | Report contents | Includes plugin/WP/PHP versions, debug constants, all settings, log dir + writable status, last 25 log lines. | | |
| G3 | Report does not leak secrets | No DB password, no `AUTH_KEY`, no full file paths beyond uploads dir. | | |

## H. Logging

| # | Scenario | Expected | Result | Notes |
|---|---|---|---|---|
| H1 | `uploads/rm-sh-logs/` exists after activation | Yes. Contains `index.html` + `.htaccess` with `Require all denied`. | | |
| H2 | Direct browse to `/wp-content/uploads/rm-sh-logs/guard-YYYY-MM-DD.log` | 403 (Apache) — confirms `.htaccess` is honored. (Skip on Nginx; document.) | | |
| H3 | Block events log without Debug mode on | Yes. | | |
| H4 | `firewall.match` events log only with Debug mode on | Confirmed. | | |

## I. Conflict sweep (per agency CLAUDE.md §5.4)

Activate Security Hardening alongside each, browse admin + frontend, save a post, watch `debug.log`.

| # | Companion | Result | Notes |
|---|---|---|---|
| I1 | Yoast SEO | | |
| I2 | Rank Math | | |
| I3 | WP Rocket | | |
| I4 | LiteSpeed Cache | | |
| I5 | Wordfence | | |
| I6 | Solid Security | | |
| I7 | Oxygen Builder | | |
| I8 | Elementor | | |
| I9 | Bricks | | |
| I10 | Gravity Forms (submit a form with rich-text content) | | |
| I11 | WPForms | | |
| I12 | Fluent Forms | | |

Record any incompatibility in `COMPATIBILITY.md` even if just "no issues".

## J. Pre-release sign-off

- [ ] All A–H rows pass on staging
- [ ] Conflict sweep (I) recorded; `COMPATIBILITY.md` updated
- [ ] `CHANGELOG.md` user-facing notes finalised
- [ ] Version `0.1.0` consistent across header, `RM_SH_VERSION`, `readme.txt` Stable tag, `CHANGELOG.md`
- [ ] No `var_dump` / `print_r` / commented-out blocks
- [ ] Zip builds without `.git`, `node_modules`, `tests/`

**Tester signature:** `___________________________`
**Sign-off date:** `___________________________`

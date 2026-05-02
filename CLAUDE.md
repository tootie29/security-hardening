# CLAUDE.md — RichardMedina Security Hardening

Plugin-specific overrides on top of the agency-wide CLAUDE.md.

## Identity

- Slug: `richardmedina-security-hardening`
- Short prefix: `sh`
- Namespace: `RichardMedina\SecurityHardening`
- Function/hook prefix: `rm_sh_`
- Option key: `rm_sh_settings` (single array)
- Log dir: `wp-content/uploads/rm-sh-logs/` (htaccess-protected)

## Composer

Not used. Hand-rolled PSR-4 autoloader at `src/Autoloader.php` is loaded directly from the bootstrap.

## Multisite

Out of scope for v0.1. Activation is refused on multisite, and a notice is shown if the plugin file is loaded under multisite for any other reason.

## Scope guardrails (do not exceed without an explicit prompt)

In v0.1 the plugin only does:

1. **Request firewall** — pattern-based scanning of `$_GET`, `$_POST`, optional cookies, and selected headers.
2. **Hardening toggles** — XML-RPC, uploads PHP block, user enumeration, REST users endpoint, generator meta, DISALLOW_FILE_EDIT advisory, application passwords.

Out of scope for v0.1 (do not add unless asked):
- File integrity scanning
- Malware scanning
- File quarantine / cleaning
- Login hardening (rate-limit, 2FA, hidden login URL)
- Email alerts
- Remote signature updates

## Risk rules unique to this plugin

- **Block mode can take the site down.** Default is Monitor. Any change to the firewall scanner must keep Monitor mode side-effect-free (log only, never `exit`).
- **Uploads `.htaccess` is shared.** Always wrap our managed block in the `# BEGIN RichardMedina Security Hardening` / `# END` markers. Never rewrite the entire file. The uninstall handler removes only our block.
- **Allowlists are first-class.** Any new inspection bucket must respect the IP, URL, and parameter allowlists.

## When adding new firewall signatures

- One signature per pattern; label format `category.specifier` (e.g. `sqli.union_select`).
- Test the pattern against `tests/fixtures/firewall-corpus.json` (TODO — corpus not yet committed).
- Avoid signatures that match common rich-text content unless the parameter is in the default allowlist.

## When adding new hardening toggles

- Default to **off** unless the change is universally safe and reversible.
- Document the user-visible side effect in `COMPATIBILITY.md`.
- If the toggle writes to the filesystem, gate it behind an `admin_init` enforcement that is idempotent and uses BEGIN/END markers.

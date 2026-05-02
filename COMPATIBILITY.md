# COMPATIBILITY

## Tested with

- WordPress: 6.4 – 6.7
- PHP: 8.1, 8.2, 8.3
- MySQL/MariaDB: defaults shipped with LocalWP

## Known conflicts

_None recorded yet. Update this section when something is observed in the field._

## Recommended companions

- **Wordfence / Solid Security** — Security Hardening is intentionally narrow and does not replace a full security suite. Run alongside.

## Notes

- The uploads-folder PHP block is written to `wp-content/uploads/.htaccess`. This is **only enforced on Apache**. Nginx hosts must add an equivalent location block in their server config — Security Hardening does not manage Nginx.
- Disabling XML-RPC will break Jetpack remote management, the WordPress mobile app, and any pingback/trackback workflows. Confirm none of these are needed before enabling.
- Removing the `/wp/v2/users` REST endpoint affects unauthenticated requests only. Authenticated requests still see the endpoint, so block editor user pickers continue to work.

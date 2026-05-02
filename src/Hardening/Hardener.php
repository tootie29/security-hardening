<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Hardening;

use RichardMedina\SecurityHardening\Support\Logger;
use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class Hardener {

	public const UPLOADS_HTACCESS_MARKER = '# BEGIN RichardMedina Security Hardening';
	public const UPLOADS_HTACCESS_END    = '# END RichardMedina Security Hardening';

	public function register(): void {
		if ( Settings::get( 'harden_disable_xmlrpc', true ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter( 'wp_headers', static function ( $headers ) {
				if ( is_array( $headers ) ) {
					unset( $headers['X-Pingback'] );
				}
				return $headers;
			} );
		}

		if ( Settings::get( 'harden_remove_generator', true ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( Settings::get( 'harden_block_user_enum', true ) ) {
			add_action( 'init', [ $this, 'block_author_enum' ] );
		}

		if ( Settings::get( 'harden_disable_rest_users', true ) ) {
			add_filter( 'rest_endpoints', [ $this, 'restrict_rest_user_endpoints' ] );
		}

		if ( Settings::get( 'harden_restrict_rest_external', false ) ) {
			add_filter( 'rest_authentication_errors', [ $this, 'restrict_rest_external' ], 99 );
		}

		if ( Settings::get( 'harden_disable_app_passwords', false ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		if (
			Settings::get( 'harden_disable_plugin_install', false )
			|| Settings::get( 'harden_disable_plugin_edit', false )
			|| Settings::get( 'harden_disable_core_update', false )
		) {
			add_filter( 'map_meta_cap', [ $this, 'deny_admin_caps' ], 10, 2 );
		}

		if ( Settings::get( 'harden_disable_file_edit', true ) ) {
			add_action( 'admin_init', [ $this, 'warn_if_file_edit_enabled' ] );
		}

		// Uploads .htaccess: enforce on settings save and on plugin load (cheap idempotent check).
		if ( Settings::get( 'harden_block_php_uploads', true ) ) {
			add_action( 'admin_init', [ $this, 'enforce_uploads_php_block' ] );
		} else {
			add_action( 'admin_init', [ $this, 'remove_uploads_php_block' ] );
		}
	}

	public function block_author_enum(): void {
		if ( is_admin() ) {
			return;
		}
		// Only act on actual author enumeration attempts on the front end.
		if ( ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$author = $_GET['author']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( is_numeric( $author ) ) {
			Logger::block( 'hardening.author_enum', [
				'ip' => isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '',
			] );
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Deny primitive caps used by the plugin install / file editor / core update screens.
	 *
	 * Using map_meta_cap with `do_not_allow` short-circuits the cap check for every
	 * user, including super admins. This is the recommended way to block these
	 * actions without touching wp-config.php constants.
	 *
	 * @param array<int,string> $caps
	 */
	public function deny_admin_caps( array $caps, string $cap ): array {
		$denied = [];

		if ( Settings::get( 'harden_disable_plugin_install', false ) ) {
			$denied[] = 'install_plugins';
			$denied[] = 'upload_plugins';
		}
		if ( Settings::get( 'harden_disable_plugin_edit', false ) ) {
			$denied[] = 'edit_plugins';
		}
		if ( Settings::get( 'harden_disable_core_update', false ) ) {
			$denied[] = 'update_core';
		}

		if ( in_array( $cap, $denied, true ) ) {
			return [ 'do_not_allow' ];
		}

		return $caps;
	}

	/**
	 * Block REST API requests that originate from outside this site.
	 *
	 * Allows when:
	 *  - Origin or Referer matches the site host (covers admin block editor + same-origin frontend)
	 *  - REMOTE_ADDR is loopback (covers wp-cron, server-to-server localhost calls)
	 *
	 * Otherwise denies with 403. Cookie-authenticated admin requests still pass
	 * because they are sent same-origin by the browser.
	 *
	 * @param mixed $errors
	 */
	public function restrict_rest_external( $errors ) {
		if ( $errors instanceof \WP_Error ) {
			return $errors;
		}

		$home_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		if ( $home_host === '' ) {
			return $errors;
		}

		$origin  = isset( $_SERVER['HTTP_ORIGIN'] ) ? (string) $_SERVER['HTTP_ORIGIN'] : '';
		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? (string) $_SERVER['HTTP_REFERER'] : '';

		$origin_host  = $origin !== '' ? (string) wp_parse_url( $origin, PHP_URL_HOST ) : '';
		$referer_host = $referer !== '' ? (string) wp_parse_url( $referer, PHP_URL_HOST ) : '';

		// Any present Origin/Referer must match. A mismatched one is a hard fail —
		// the loopback exemption below only applies to header-less server-to-server calls.
		$has_header     = ( $origin_host !== '' || $referer_host !== '' );
		$matches_origin = ( $origin_host !== '' && strcasecmp( $origin_host, $home_host ) === 0 );
		$matches_ref    = ( $referer_host !== '' && strcasecmp( $referer_host, $home_host ) === 0 );

		if ( $has_header ) {
			if ( $matches_origin || $matches_ref ) {
				return $errors;
			}
		} else {
			$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
			if ( in_array( $ip, [ '127.0.0.1', '::1' ], true ) ) {
				return $errors;
			}
		}

		Logger::block( 'hardening.rest_external_blocked', [
			'ip'      => isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '',
			'origin'  => $origin_host,
			'referer' => $referer_host,
			'route'   => isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '',
		] );

		return new \WP_Error(
			'rest_external_blocked',
			__( 'REST API requests from outside this site are disabled.', 'richardmedina-security-hardening' ),
			[ 'status' => 403 ]
		);
	}

	/** @param array<string,mixed> $endpoints */
	public function restrict_rest_user_endpoints( array $endpoints ): array {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( [ '/wp/v2/users', '/wp/v2/users/(?P<id>[\\d]+)' ] as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	public function warn_if_file_edit_enabled(): void {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return;
		}
		add_action( 'admin_notices', static function (): void {
			if ( ! current_user_can( 'manage_options' ) ) {
				return;
			}
			echo '<div class="notice notice-warning"><p><strong>RichardMedina Security Hardening:</strong> ';
			echo esc_html__( 'Theme/plugin file editing is enabled. Add', 'richardmedina-security-hardening' );
			echo ' <code>define( \'DISALLOW_FILE_EDIT\', true );</code> ';
			echo esc_html__( 'to wp-config.php to disable it.', 'richardmedina-security-hardening' );
			echo '</p></div>';
		} );
	}

	public function enforce_uploads_php_block(): void {
		$dir = $this->uploads_basedir();
		if ( $dir === '' ) {
			return;
		}
		$file = $dir . '/.htaccess';
		$existing = is_readable( $file ) ? (string) @file_get_contents( $file ) : '';

		if ( str_contains( $existing, self::UPLOADS_HTACCESS_MARKER ) ) {
			return;
		}

		$block = self::UPLOADS_HTACCESS_MARKER . "\n";
		$block .= "<FilesMatch \"\\.(?:php[0-9]?|phtml|phar)$\">\n";
		$block .= "\tRequire all denied\n";
		$block .= "\tDeny from all\n";
		$block .= "</FilesMatch>\n";
		$block .= self::UPLOADS_HTACCESS_END . "\n";

		$new = trim( $existing ) === '' ? $block : trim( $existing ) . "\n\n" . $block;

		if ( @file_put_contents( $file, $new, LOCK_EX ) === false ) {
			Logger::warn( 'hardening.uploads_htaccess_write_failed', [ 'file' => $file ] );
		}
	}

	public function remove_uploads_php_block(): void {
		$dir = $this->uploads_basedir();
		if ( $dir === '' ) {
			return;
		}
		$file = $dir . '/.htaccess';
		if ( ! is_readable( $file ) ) {
			return;
		}
		$existing = (string) @file_get_contents( $file );
		if ( ! str_contains( $existing, self::UPLOADS_HTACCESS_MARKER ) ) {
			return;
		}
		$pattern = '/' . preg_quote( self::UPLOADS_HTACCESS_MARKER, '/' )
			. '.*?' . preg_quote( self::UPLOADS_HTACCESS_END, '/' ) . '\n?/s';
		$new = preg_replace( $pattern, '', $existing );
		@file_put_contents( $file, (string) $new, LOCK_EX );
	}

	private function uploads_basedir(): string {
		$uploads = wp_upload_dir( null, false );
		return ! empty( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';
	}
}

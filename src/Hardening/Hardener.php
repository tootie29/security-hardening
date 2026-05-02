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

		if ( Settings::get( 'harden_disable_app_passwords', false ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
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

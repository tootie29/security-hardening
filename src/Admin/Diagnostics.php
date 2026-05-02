<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Admin;

use RichardMedina\SecurityHardening\Support\Logger;
use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class Diagnostics {

	public const ACTION = 'rm_sh_run_diagnostics';
	public const NONCE  = 'rm_sh_diag';

	public function register(): void {
		add_action( 'admin_post_' . self::ACTION, [ $this, 'handle' ] );
	}

	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'richardmedina-security-hardening' ), '', [ 'response' => 403 ] );
		}
		check_admin_referer( self::NONCE );

		$report = self::build_report();
		set_transient( 'rm_sh_diag_report', $report, MINUTE_IN_SECONDS * 5 );

		wp_safe_redirect( add_query_arg( [
			'page' => 'rm-sh-settings',
			'tab'  => 'diagnostics',
		], admin_url( 'options-general.php' ) ) );
		exit;
	}

	public static function build_report(): string {
		global $wp_version, $wpdb;

		$lines = [];
		$lines[] = 'RichardMedina Security Hardening diagnostics — ' . gmdate( 'c' );
		$lines[] = str_repeat( '-', 60 );
		$lines[] = 'Plugin version:       ' . RM_SH_VERSION;
		$lines[] = 'WordPress version:    ' . $wp_version;
		$lines[] = 'PHP version:          ' . PHP_VERSION;
		$lines[] = 'DB version:           ' . ( $wpdb ? $wpdb->db_version() : 'n/a' );
		$lines[] = 'Multisite:            ' . ( is_multisite() ? 'yes' : 'no' );
		$lines[] = 'Active theme:         ' . wp_get_theme()->get( 'Name' ) . ' ' . wp_get_theme()->get( 'Version' );
		$lines[] = '';
		$lines[] = 'Constants:';
		$lines[] = '  WP_DEBUG              = ' . self::bool( defined( 'WP_DEBUG' ) && WP_DEBUG );
		$lines[] = '  WP_DEBUG_LOG          = ' . self::bool( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG );
		$lines[] = '  SCRIPT_DEBUG          = ' . self::bool( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG );
		$lines[] = '  DISALLOW_FILE_EDIT    = ' . self::bool( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
		$lines[] = '  DISABLE_WP_CRON       = ' . self::bool( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON );
		$lines[] = '';
		$lines[] = 'Settings:';
		foreach ( Settings::all() as $k => $v ) {
			$display = is_bool( $v ) ? self::bool( $v ) : ( is_scalar( $v ) ? (string) $v : wp_json_encode( $v ) );
			$display = mb_substr( (string) $display, 0, 200 );
			$lines[] = '  ' . str_pad( (string) $k, 32 ) . ' = ' . $display;
		}
		$lines[] = '';
		$lines[] = 'Log directory:        ' . Logger::log_dir();
		$lines[] = 'Log dir writable:     ' . self::bool( is_writable( Logger::log_dir() ) );
		$lines[] = '';
		$lines[] = 'Recent log lines:';
		$tail = Logger::tail( 25 );
		$lines[] = $tail !== '' ? $tail : '  (empty)';

		return implode( "\n", $lines );
	}

	private static function bool( bool $v ): string {
		return $v ? 'true' : 'false';
	}
}

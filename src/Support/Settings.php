<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Support;

defined( 'ABSPATH' ) || exit;

final class Settings {

	public const OPTION_KEY = 'rm_sh_settings';

	public static function defaults(): array {
		return [
			'enabled'                  => true,
			'debug_mode'               => false,

			// Firewall.
			'firewall_mode'            => 'monitor', // off | monitor | block
			'firewall_check_get'       => true,
			'firewall_check_post'      => true,
			'firewall_check_cookie'    => false,
			'firewall_check_headers'   => true,
			'firewall_ip_allowlist'    => '',
			'firewall_url_allowlist'   => "/wp-admin/admin-ajax.php\n/wp-json/",
			'firewall_param_allowlist' => 'content,post_content,description',

			// Hardening.
			'harden_disable_file_edit'   => true,
			'harden_disable_xmlrpc'      => true,
			'harden_block_php_uploads'   => true,
			'harden_block_user_enum'     => true,
			'harden_remove_generator'    => true,
			'harden_disable_rest_users'  => true,
			'harden_disable_app_passwords' => false,
		];
	}

	public static function all(): array {
		$opts = get_option( self::OPTION_KEY, [] );
		if ( ! is_array( $opts ) ) {
			$opts = [];
		}
		return array_merge( self::defaults(), $opts );
	}

	/** @param mixed $default */
	public static function get( string $key, $default = null ) {
		$all = self::all();
		return $all[ $key ] ?? $default;
	}

	/**
	 * Sanitize callback for register_setting().
	 *
	 * Validates every key explicitly. Unknown keys dropped.
	 *
	 * @param mixed $input
	 */
	public static function sanitize( $input ): array {
		$defaults = self::defaults();
		$clean    = $defaults;

		if ( ! is_array( $input ) ) {
			return $defaults;
		}

		$bool_keys = [
			'enabled', 'debug_mode',
			'firewall_check_get', 'firewall_check_post',
			'firewall_check_cookie', 'firewall_check_headers',
			'harden_disable_file_edit', 'harden_disable_xmlrpc',
			'harden_block_php_uploads', 'harden_block_user_enum',
			'harden_remove_generator', 'harden_disable_rest_users',
			'harden_disable_app_passwords',
		];

		foreach ( $bool_keys as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}

		$mode = $input['firewall_mode'] ?? 'monitor';
		$clean['firewall_mode'] = in_array( $mode, [ 'off', 'monitor', 'block' ], true ) ? $mode : 'monitor';

		$text_keys = [ 'firewall_ip_allowlist', 'firewall_url_allowlist', 'firewall_param_allowlist' ];
		foreach ( $text_keys as $key ) {
			$value = isset( $input[ $key ] ) ? (string) $input[ $key ] : '';
			$clean[ $key ] = sanitize_textarea_field( $value );
		}

		return $clean;
	}
}

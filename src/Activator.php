<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening;

use RichardMedina\SecurityHardening\Support\Settings;
use RichardMedina\SecurityHardening\Support\Logger;

defined( 'ABSPATH' ) || exit;

final class Activator {

	public static function activate(): void {
		if ( is_multisite() ) {
			deactivate_plugins( plugin_basename( RM_SH_FILE ) );
			wp_die(
				esc_html__( 'RichardMedina Security Hardening does not support multisite.', 'richardmedina-security-hardening' ),
				esc_html__( 'Plugin activation failed', 'richardmedina-security-hardening' ),
				[ 'back_link' => true ]
			);
		}

		$existing = get_option( Settings::OPTION_KEY, [] );
		if ( ! is_array( $existing ) || empty( $existing ) ) {
			update_option( Settings::OPTION_KEY, Settings::defaults(), false );
		}

		update_option( 'rm_sh_version', RM_SH_VERSION, false );

		Logger::ensure_log_dir();
	}
}

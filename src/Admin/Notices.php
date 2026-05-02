<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Admin;

use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class Notices {

	public function register(): void {
		add_action( 'admin_notices', [ $this, 'maybe_render' ] );
	}

	public function maybe_render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$on_settings = $screen && isset( $screen->id ) && str_contains( (string) $screen->id, 'rm-sh-settings' );

		if ( ! Settings::get( 'enabled', true ) && ! $on_settings ) {
			echo '<div class="notice notice-warning"><p><strong>RichardMedina Security Hardening</strong> ';
			echo esc_html__( 'is currently disabled. Enable it on the settings page.', 'richardmedina-security-hardening' );
			echo '</p></div>';
		}

		if ( Settings::get( 'firewall_mode', 'monitor' ) === 'monitor' && $on_settings ) {
			echo '<div class="notice notice-info"><p><strong>RichardMedina Security Hardening:</strong> ';
			echo esc_html__( 'The firewall is in monitor mode. Hits are logged but not blocked.', 'richardmedina-security-hardening' );
			echo '</p></div>';
		}
	}
}

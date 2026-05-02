<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening;

use RichardMedina\SecurityHardening\Admin\Diagnostics;
use RichardMedina\SecurityHardening\Admin\Notices;
use RichardMedina\SecurityHardening\Admin\SettingsPage;
use RichardMedina\SecurityHardening\Firewall\RequestFirewall;
use RichardMedina\SecurityHardening\Hardening\Hardener;
use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class Plugin {

	private static ?Plugin $instance = null;

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	public function boot(): void {
		add_action( 'init', static function (): void {
			load_plugin_textdomain( 'richardmedina-security-hardening', false, dirname( plugin_basename( RM_SH_FILE ) ) . '/languages' );
		} );

		( new Notices() )->register();

		if ( ! Settings::get( 'enabled', true ) ) {
			if ( is_admin() ) {
				( new SettingsPage() )->register();
				( new Diagnostics() )->register();
			}
			return;
		}

		// Request firewall must be early — runs at plugins_loaded priority 1 via this method.
		( new RequestFirewall() )->register();

		// Hardening attaches to a mix of init/template/REST hooks.
		( new Hardener() )->register();

		if ( is_admin() ) {
			( new SettingsPage() )->register();
			( new Diagnostics() )->register();
		}
	}

	private function __construct() {}
	private function __clone() {}
}

<?php
/**
 * Plugin Name:       RichardMedina Security Hardening
 * Plugin URI:        https://richardmedina.com.au/plugins/richardmedina-security-hardening
 * Description:       Hardens WordPress against injection attempts and common attack vectors via a request firewall and a set of hardening toggles.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Richard Medina
 * Author URI:        https://richardmedina.com.au
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       richardmedina-security-hardening
 * Domain Path:       /languages
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

define( 'RM_SH_VERSION', '0.1.0' );
define( 'RM_SH_FILE', __FILE__ );
define( 'RM_SH_DIR', plugin_dir_path( __FILE__ ) );
define( 'RM_SH_URL', plugin_dir_url( __FILE__ ) );
define( 'RM_SH_SLUG', 'richardmedina-security-hardening' );

if ( is_multisite() ) {
	add_action( 'admin_notices', static function (): void {
		echo '<div class="notice notice-error"><p><strong>RichardMedina Security Hardening</strong> does not support multisite in v0.1.</p></div>';
	} );
	return;
}

require_once RM_SH_DIR . 'src/Autoloader.php';
\RichardMedina\SecurityHardening\Autoloader::register();

register_activation_hook( __FILE__, [ \RichardMedina\SecurityHardening\Activator::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ \RichardMedina\SecurityHardening\Deactivator::class, 'deactivate' ] );

add_action( 'plugins_loaded', static function (): void {
	\RichardMedina\SecurityHardening\Plugin::instance()->boot();
}, 1 );

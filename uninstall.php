<?php
/**
 * Uninstall handler for RichardMedina Security Hardening.
 *
 * Removes options, log directory contents, and the uploads/.htaccess block.
 */

declare( strict_types=1 );

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'rm_sh_settings' );
delete_option( 'rm_sh_version' );
delete_transient( 'rm_sh_diag_report' );

$uploads = wp_upload_dir( null, false );
if ( ! empty( $uploads['basedir'] ) ) {
	$basedir = (string) $uploads['basedir'];

	// Remove log directory.
	$log_dir = $basedir . '/rm-sh-logs';
	if ( is_dir( $log_dir ) ) {
		$files = glob( $log_dir . '/*' );
		if ( is_array( $files ) ) {
			foreach ( $files as $file ) {
				if ( is_file( $file ) ) {
					@unlink( $file );
				}
			}
		}
		// Remove dotfiles too.
		foreach ( [ '.htaccess', 'index.html' ] as $hidden ) {
			$p = $log_dir . '/' . $hidden;
			if ( is_file( $p ) ) {
				@unlink( $p );
			}
		}
		@rmdir( $log_dir );
	}

	// Strip our managed block from uploads/.htaccess.
	$ht = $basedir . '/.htaccess';
	if ( is_readable( $ht ) ) {
		$contents = (string) @file_get_contents( $ht );
		$pattern  = '/# BEGIN RichardMedina Security Hardening.*?# END RichardMedina Security Hardening\n?/s';
		$cleaned  = preg_replace( $pattern, '', $contents );
		if ( is_string( $cleaned ) ) {
			$cleaned = trim( $cleaned );
			if ( $cleaned === '' ) {
				@unlink( $ht );
			} else {
				@file_put_contents( $ht, $cleaned . "\n", LOCK_EX );
			}
		}
	}
}

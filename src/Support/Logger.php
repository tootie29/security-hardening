<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Support;

defined( 'ABSPATH' ) || exit;

final class Logger {

	public const SUBDIR = 'rm-sh-logs';

	public static function log_dir(): string {
		$uploads = wp_upload_dir( null, false );
		return trailingslashit( $uploads['basedir'] ) . self::SUBDIR;
	}

	public static function ensure_log_dir(): void {
		$dir = self::log_dir();
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$index = $dir . '/index.html';
		if ( ! file_exists( $index ) ) {
			@file_put_contents( $index, '' );
		}

		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			@file_put_contents( $htaccess, "Require all denied\nDeny from all\n" );
		}
	}

	public static function info( string $event, array $context = [] ): void {
		self::write( 'info', $event, $context );
	}

	public static function warn( string $event, array $context = [] ): void {
		self::write( 'warn', $event, $context );
	}

	public static function block( string $event, array $context = [] ): void {
		self::write( 'block', $event, $context );
	}

	private static function write( string $level, string $event, array $context ): void {
		if ( $level !== 'block' && ! Settings::get( 'debug_mode', false ) ) {
			return;
		}

		self::ensure_log_dir();

		$file = self::log_dir() . '/guard-' . gmdate( 'Y-m-d' ) . '.log';
		$line = sprintf(
			"[%s] [%s] %s %s\n",
			gmdate( 'c' ),
			strtoupper( $level ),
			$event,
			$context ? wp_json_encode( $context ) : ''
		);

		@file_put_contents( $file, $line, FILE_APPEND | LOCK_EX );
	}

	public static function tail( int $lines = 50 ): string {
		$file = self::log_dir() . '/guard-' . gmdate( 'Y-m-d' ) . '.log';
		if ( ! is_readable( $file ) ) {
			return '';
		}
		$all = @file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		if ( ! is_array( $all ) ) {
			return '';
		}
		return implode( "\n", array_slice( $all, -$lines ) );
	}
}

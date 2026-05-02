<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening;

defined( 'ABSPATH' ) || exit;

final class Autoloader {

	private const PREFIX  = 'RichardMedina\\SecurityHardening\\';
	private const BASEDIR = __DIR__ . '/';

	public static function register(): void {
		spl_autoload_register( [ self::class, 'load' ] );
	}

	public static function load( string $class ): void {
		if ( ! str_starts_with( $class, self::PREFIX ) ) {
			return;
		}

		$relative = substr( $class, strlen( self::PREFIX ) );
		$path     = self::BASEDIR . str_replace( '\\', '/', $relative ) . '.php';

		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
}

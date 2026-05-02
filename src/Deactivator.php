<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening;

defined( 'ABSPATH' ) || exit;

final class Deactivator {

	public static function deactivate(): void {
		// Intentionally minimal. Settings and logs persist on deactivation.
		// Cleanup happens in uninstall.php.
	}
}

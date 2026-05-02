<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Firewall;

defined( 'ABSPATH' ) || exit;

final class Signatures {

	/**
	 * Pattern => label. Patterns must be valid PCRE; case-insensitive flag added at match time.
	 */
	public static function patterns(): array {
		return [
			// SQL injection.
			'/\bunion\b\s+(?:all\s+)?\bselect\b/i'                            => 'sqli.union_select',
			'/\bselect\b[\s\S]{0,200}\bfrom\b\s+information_schema\b/i'       => 'sqli.information_schema',
			'/\b(?:and|or)\b\s+\d+\s*=\s*\d+(?:\s*--|\s*#)/i'                 => 'sqli.tautology',
			'/\b(?:sleep|benchmark|pg_sleep)\s*\(/i'                          => 'sqli.time_based',
			'/\bload_file\s*\(|\binto\s+outfile\b|\binto\s+dumpfile\b/i'      => 'sqli.file_io',
			'/;\s*(?:drop|truncate|alter)\s+table\b/i'                        => 'sqli.ddl_chain',

			// XSS.
			'/<\s*script\b[^>]*>/i'                                           => 'xss.script_tag',
			'/<\s*iframe\b[^>]*>/i'                                           => 'xss.iframe_tag',
			'/javascript\s*:/i'                                               => 'xss.javascript_uri',
			'/\bon(?:error|load|click|mouseover|focus|blur)\s*=/i'            => 'xss.event_handler',
			'/<\s*svg\b[^>]*\bon\w+\s*=/i'                                    => 'xss.svg_handler',

			// LFI/RFI/path traversal.
			'/(?:\.\.\/){2,}/'                                                => 'lfi.traversal',
			'/(?:php|data|file|expect|phar|zip):\/\//i'                       => 'rfi.wrapper',
			'/\/etc\/passwd|\/proc\/self\/environ/i'                          => 'lfi.sensitive_path',

			// Web shell / RCE patterns.
			'/\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i'    => 'rce.eval_decoded',
			'/\b(?:passthru|shell_exec|system|popen|proc_open)\s*\(/i'        => 'rce.shell_function',
			'/\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'               => 'rce.assert_input',
			'/\b(?:c99|r57|wso|filesman)\b/i'                                 => 'rce.known_shell_name',
		];
	}
}

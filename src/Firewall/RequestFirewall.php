<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Firewall;

use RichardMedina\SecurityHardening\Support\Logger;
use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class RequestFirewall {

	public function register(): void {
		// Plugin::boot already runs at plugins_loaded priority 1; inspect immediately.
		$this->inspect();
	}

	private function inspect(): void {
		$mode = Settings::get( 'firewall_mode', 'monitor' );
		if ( $mode === 'off' ) {
			return;
		}

		// Skip CLI and cron.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}

		$ip          = $this->client_ip();
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';

		if ( $this->ip_allowed( $ip ) ) {
			return;
		}
		if ( $this->url_allowed( $request_uri ) ) {
			return;
		}

		$param_allowlist = $this->param_allowlist();
		$patterns        = Signatures::patterns();

		$buckets = [];
		if ( Settings::get( 'firewall_check_get', true ) && ! empty( $_GET ) ) {
			$buckets['GET'] = wp_unslash( $_GET ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		if ( Settings::get( 'firewall_check_post', true ) && ! empty( $_POST ) ) {
			$buckets['POST'] = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		}
		if ( Settings::get( 'firewall_check_cookie', false ) && ! empty( $_COOKIE ) ) {
			$buckets['COOKIE'] = wp_unslash( $_COOKIE );
		}
		if ( Settings::get( 'firewall_check_headers', true ) ) {
			$buckets['HEADER'] = [
				'User-Agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '',
				'Referer'    => isset( $_SERVER['HTTP_REFERER'] ) ? (string) $_SERVER['HTTP_REFERER'] : '',
			];
		}

		foreach ( $buckets as $bucket => $data ) {
			$hit = $this->scan( $data, $patterns, $param_allowlist );
			if ( $hit !== null ) {
				$this->handle_hit( $mode, $bucket, $hit, $ip, $request_uri );
				return;
			}
		}
	}

	/**
	 * @param mixed $data
	 * @return array{key:string,value:string,signature:string}|null
	 */
	private function scan( $data, array $patterns, array $param_allowlist, string $key_path = '' ): ?array {
		if ( is_array( $data ) ) {
			foreach ( $data as $k => $v ) {
				$next = $key_path === '' ? (string) $k : $key_path . '.' . $k;
				if ( in_array( (string) $k, $param_allowlist, true ) ) {
					continue;
				}
				$hit = $this->scan( $v, $patterns, $param_allowlist, $next );
				if ( $hit !== null ) {
					return $hit;
				}
			}
			return null;
		}

		if ( ! is_string( $data ) ) {
			return null;
		}

		$value = $data;
		// Decode once to catch URL-encoded payloads.
		$decoded = rawurldecode( $value );
		$candidates = $value === $decoded ? [ $value ] : [ $value, $decoded ];

		foreach ( $candidates as $candidate ) {
			foreach ( $patterns as $pattern => $label ) {
				if ( @preg_match( $pattern, $candidate ) === 1 ) {
					return [
						'key'       => $key_path,
						'value'     => mb_substr( $candidate, 0, 200 ),
						'signature' => $label,
					];
				}
			}
		}

		return null;
	}

	private function handle_hit( string $mode, string $bucket, array $hit, string $ip, string $url ): void {
		$context = [
			'ip'        => $ip,
			'url'       => $url,
			'bucket'    => $bucket,
			'param'     => $hit['key'],
			'signature' => $hit['signature'],
			'sample'    => $hit['value'],
		];

		if ( $mode === 'block' ) {
			Logger::block( 'firewall.blocked', $context );
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo "Forbidden\n";
			exit;
		}

		Logger::warn( 'firewall.match', $context );
	}

	private function client_ip(): string {
		$candidates = [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' ];
		foreach ( $candidates as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) {
				continue;
			}
			$value = (string) $_SERVER[ $key ];
			$first = trim( explode( ',', $value )[0] );
			if ( filter_var( $first, FILTER_VALIDATE_IP ) !== false ) {
				return $first;
			}
		}
		return '0.0.0.0';
	}

	private function ip_allowed( string $ip ): bool {
		$raw = (string) Settings::get( 'firewall_ip_allowlist', '' );
		if ( $raw === '' ) {
			return false;
		}
		$list = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ?: [] ) );
		return in_array( $ip, $list, true );
	}

	private function url_allowed( string $url ): bool {
		$raw = (string) Settings::get( 'firewall_url_allowlist', '' );
		if ( $raw === '' ) {
			return false;
		}
		$list = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ?: [] ) );
		foreach ( $list as $needle ) {
			if ( $needle === '' ) {
				continue;
			}
			if ( str_starts_with( $url, $needle ) || str_contains( $url, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	private function param_allowlist(): array {
		$raw = (string) Settings::get( 'firewall_param_allowlist', '' );
		if ( $raw === '' ) {
			return [];
		}
		return array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ?: [] ) ) );
	}
}

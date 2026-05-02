<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Admin;

use RichardMedina\SecurityHardening\Support\Logger;
use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class SettingsPage {

	public const PAGE_SLUG = 'rm-sh-settings';
	public const GROUP     = 'rm_sh_settings_group';

	private const HARDEN_KEYS = [
		'harden_disable_xmlrpc',
		'harden_block_php_uploads',
		'harden_block_user_enum',
		'harden_disable_rest_users',
		'harden_remove_generator',
		'harden_disable_file_edit',
		'harden_disable_app_passwords',
		'harden_disable_plugin_install',
		'harden_disable_plugin_edit',
		'harden_disable_core_update',
		'harden_restrict_rest_external',
	];

	public function register(): void {
		add_action( 'admin_menu', [ $this, 'register_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_post_rm_sh_reset_defaults', [ $this, 'handle_reset' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );
		add_filter( 'plugin_action_links_' . plugin_basename( RM_SH_FILE ), [ $this, 'add_action_links' ] );
	}

	/** @param array<int|string,string> $links */
	public function add_action_links( array $links ): array {
		$url      = admin_url( 'options-general.php?page=' . self::PAGE_SLUG );
		$settings = sprintf(
			'<a href="%s">%s</a>',
			esc_url( $url ),
			esc_html__( 'Settings', 'richardmedina-security-hardening' )
		);
		array_unshift( $links, $settings );
		return $links;
	}

	public function enqueue( string $hook ): void {
		if ( $hook !== 'settings_page_' . self::PAGE_SLUG ) {
			return;
		}
		wp_enqueue_style(
			'rm-sh-admin',
			RM_SH_URL . 'assets/admin/admin.css',
			[],
			RM_SH_VERSION
		);
		wp_enqueue_script(
			'rm-sh-admin',
			RM_SH_URL . 'assets/admin/admin.js',
			[],
			RM_SH_VERSION,
			true
		);
	}

	public function register_menu(): void {
		add_options_page(
			__( 'RichardMedina Security Hardening', 'richardmedina-security-hardening' ),
			__( 'RM Hardening', 'richardmedina-security-hardening' ),
			'manage_options',
			self::PAGE_SLUG,
			[ $this, 'render_page' ]
		);
	}

	public function register_settings(): void {
		register_setting(
			self::GROUP,
			Settings::OPTION_KEY,
			[
				'type'              => 'array',
				'sanitize_callback' => [ Settings::class, 'sanitize' ],
				'default'           => Settings::defaults(),
			]
		);
	}

	public function handle_reset(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'richardmedina-security-hardening' ), '', [ 'response' => 403 ] );
		}
		check_admin_referer( 'rm_sh_reset' );
		update_option( Settings::OPTION_KEY, Settings::defaults(), false );
		wp_safe_redirect( add_query_arg( [
			'page'    => self::PAGE_SLUG,
			'updated' => 'reset',
		], admin_url( 'options-general.php' ) ) );
		exit;
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$tabs = [
			'status'      => __( 'Status', 'richardmedina-security-hardening' ),
			'firewall'    => __( 'Firewall', 'richardmedina-security-hardening' ),
			'hardening'   => __( 'Hardening', 'richardmedina-security-hardening' ),
			'diagnostics' => __( 'Diagnostics', 'richardmedina-security-hardening' ),
		];
		$active = isset( $_GET['tab'] ) ? sanitize_key( (string) $_GET['tab'] ) : 'status'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $tabs[ $active ] ) ) {
			$active = 'status';
		}

		$opts = Settings::all();
		?>
		<div class="wrap rm-sh-wrap">
			<h1 class="screen-reader-text"><?php esc_html_e( 'RichardMedina Security Hardening', 'richardmedina-security-hardening' ); ?></h1>

			<?php $this->render_header( $opts ); ?>

			<?php if ( isset( $_GET['updated'] ) && $_GET['updated'] === 'reset' ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings reset to defaults.', 'richardmedina-security-hardening' ); ?></p></div>
			<?php endif; ?>

			<h2 class="nav-tab-wrapper">
				<?php foreach ( $tabs as $key => $label ) :
					$url   = add_query_arg( [ 'page' => self::PAGE_SLUG, 'tab' => $key ], admin_url( 'options-general.php' ) );
					$class = 'nav-tab' . ( $active === $key ? ' nav-tab-active' : '' );
					?>
					<a href="<?php echo esc_url( $url ); ?>" class="<?php echo esc_attr( $class ); ?>"><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</h2>

			<?php if ( $active === 'diagnostics' ) : ?>
				<?php $this->render_diagnostics(); ?>
			<?php else : ?>
				<form action="options.php" method="post">
					<?php settings_fields( self::GROUP ); ?>
					<input type="hidden" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[__current_tab]" value="<?php echo esc_attr( $active ); ?>" />

					<?php
					$this->render_hidden_for_inactive_tabs( $active, $opts );

					if ( $active === 'status' ) {
						$this->render_status_tab( $opts );
					} elseif ( $active === 'firewall' ) {
						$this->render_firewall_tab( $opts );
					} elseif ( $active === 'hardening' ) {
						$this->render_hardening_tab( $opts );
					}
					?>

					<div class="rm-sh-form-actions">
						<?php submit_button( __( 'Save Changes', 'richardmedina-security-hardening' ), 'primary', 'submit', false ); ?>
					</div>
				</form>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rm-sh-form-actions" onsubmit="return confirm('<?php echo esc_js( __( 'Reset all RichardMedina Security Hardening settings to defaults?', 'richardmedina-security-hardening' ) ); ?>');">
					<?php wp_nonce_field( 'rm_sh_reset' ); ?>
					<input type="hidden" name="action" value="rm_sh_reset_defaults" />
					<?php submit_button( __( 'Reset to defaults', 'richardmedina-security-hardening' ), 'delete', 'submit', false ); ?>
				</form>
			<?php endif; ?>

			<?php $this->render_footer(); ?>
		</div>
		<?php
	}

	private function render_header( array $opts ): void {
		$enabled = ! empty( $opts['enabled'] );
		$mode    = (string) ( $opts['firewall_mode'] ?? 'monitor' );

		[ $status_class, $status_label ] = $enabled
			? [ 'rm-sh-pill--success', __( 'Active', 'richardmedina-security-hardening' ) ]
			: [ 'rm-sh-pill--danger', __( 'Disabled', 'richardmedina-security-hardening' ) ];

		[ $mode_class, $mode_label ] = $this->mode_pill( $mode );

		?>
		<div class="rm-sh-header">
			<div class="rm-sh-header__brand">
				<span class="rm-sh-header__icon" aria-hidden="true">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
				</span>
				<div>
					<h2 class="rm-sh-header__title"><?php esc_html_e( 'RichardMedina Security Hardening', 'richardmedina-security-hardening' ); ?></h2>
					<p class="rm-sh-header__sub"><?php esc_html_e( 'Request firewall and hardening toggles for WordPress', 'richardmedina-security-hardening' ); ?></p>
				</div>
			</div>
			<div class="rm-sh-header__meta">
				<span class="rm-sh-pill rm-sh-pill--neutral">v<?php echo esc_html( RM_SH_VERSION ); ?></span>
				<span class="rm-sh-pill <?php echo esc_attr( $mode_class ); ?>"><?php echo esc_html( sprintf( __( 'Firewall: %s', 'richardmedina-security-hardening' ), $mode_label ) ); ?></span>
				<span class="rm-sh-pill <?php echo esc_attr( $status_class ); ?>"><span class="rm-sh-pill__dot"></span><?php echo esc_html( $status_label ); ?></span>
			</div>
		</div>
		<?php
	}

	private function render_footer(): void {
		?>
		<div class="rm-sh-footer">
			<span><?php echo esc_html( sprintf( __( 'RichardMedina Security Hardening v%s', 'richardmedina-security-hardening' ), RM_SH_VERSION ) ); ?></span>
			<span><a href="https://richardmedina.com.au" target="_blank" rel="noopener">richardmedina.com.au</a></span>
		</div>
		<?php
	}

	/** @return array{0:string,1:string} */
	private function mode_pill( string $mode ): array {
		switch ( $mode ) {
			case 'block':
				return [ 'rm-sh-pill--success', __( 'Block', 'richardmedina-security-hardening' ) ];
			case 'off':
				return [ 'rm-sh-pill--danger', __( 'Off', 'richardmedina-security-hardening' ) ];
			default:
				return [ 'rm-sh-pill--warning', __( 'Monitor', 'richardmedina-security-hardening' ) ];
		}
	}

	private function render_status_tab( array $opts ): void {
		$enabled_count = 0;
		foreach ( self::HARDEN_KEYS as $k ) {
			if ( ! empty( $opts[ $k ] ) ) {
				$enabled_count++;
			}
		}
		$total       = count( self::HARDEN_KEYS );
		$mode        = (string) ( $opts['firewall_mode'] ?? 'monitor' );
		[ $mp_class, $mp_label ] = $this->mode_pill( $mode );
		$mode_sub = $mode === 'block'
			? __( 'Matching requests blocked with HTTP 403.', 'richardmedina-security-hardening' )
			: ( $mode === 'monitor'
				? __( 'Matching requests are logged but not blocked.', 'richardmedina-security-hardening' )
				: __( 'Firewall is currently inactive.', 'richardmedina-security-hardening' ) );

		$last  = Logger::last_firewall_event();
		$size  = Logger::current_log_size();
		?>

		<div class="rm-sh-grid">
			<div class="rm-sh-card">
				<p class="rm-sh-card__label"><?php esc_html_e( 'Hardening toggles', 'richardmedina-security-hardening' ); ?></p>
				<p class="rm-sh-card__value"><?php echo esc_html( sprintf( '%d / %d', $enabled_count, $total ) ); ?></p>
				<p class="rm-sh-card__sub"><?php echo esc_html( sprintf( _n( '%d enabled', '%d enabled', $enabled_count, 'richardmedina-security-hardening' ), $enabled_count ) ); ?></p>
			</div>
			<div class="rm-sh-card">
				<p class="rm-sh-card__label"><?php esc_html_e( 'Firewall', 'richardmedina-security-hardening' ); ?></p>
				<p class="rm-sh-card__value"><span class="rm-sh-pill <?php echo esc_attr( $mp_class ); ?>"><?php echo esc_html( $mp_label ); ?></span></p>
				<p class="rm-sh-card__sub"><?php echo esc_html( $mode_sub ); ?></p>
			</div>
			<div class="rm-sh-card">
				<p class="rm-sh-card__label"><?php esc_html_e( 'Last firewall match', 'richardmedina-security-hardening' ); ?></p>
				<?php if ( $last && $last['timestamp'] ) :
					$delta = human_time_diff( $last['timestamp'], time() );
					$sig   = (string) ( $last['context']['signature'] ?? $last['event'] );
					$ip    = (string) ( $last['context']['ip'] ?? '' );
					?>
					<p class="rm-sh-card__value"><?php echo esc_html( sprintf( __( '%s ago', 'richardmedina-security-hardening' ), $delta ) ); ?></p>
					<p class="rm-sh-card__sub"><?php echo esc_html( $sig . ( $ip !== '' ? ' · ' . $ip : '' ) ); ?></p>
				<?php else : ?>
					<p class="rm-sh-card__value">—</p>
					<p class="rm-sh-card__sub"><?php esc_html_e( 'No matches today.', 'richardmedina-security-hardening' ); ?></p>
				<?php endif; ?>
			</div>
			<div class="rm-sh-card">
				<p class="rm-sh-card__label"><?php esc_html_e( 'Today\'s log file', 'richardmedina-security-hardening' ); ?></p>
				<p class="rm-sh-card__value"><?php echo esc_html( Logger::format_size( $size ) ); ?></p>
				<p class="rm-sh-card__sub"><code><?php echo esc_html( basename( Logger::current_log_path() ) ); ?></code></p>
			</div>
		</div>

		<div class="rm-sh-section">
			<div class="rm-sh-section__head">
				<h3 class="rm-sh-section__title"><?php esc_html_e( 'Plugin status', 'richardmedina-security-hardening' ); ?></h3>
				<p class="rm-sh-section__sub"><?php esc_html_e( 'Master switch and verbose logging.', 'richardmedina-security-hardening' ); ?></p>
			</div>
			<div class="rm-sh-section__body">
				<?php
				$this->render_toggle_row(
					'enabled',
					__( 'Master switch', 'richardmedina-security-hardening' ),
					__( 'When off, the firewall and hardening features are inactive. The settings page remains available.', 'richardmedina-security-hardening' ),
					! empty( $opts['enabled'] )
				);
				$this->render_toggle_row(
					'debug_mode',
					__( 'Debug mode', 'richardmedina-security-hardening' ),
					__( 'Verbose logging to wp-content/uploads/rm-sh-logs/. Block events are always logged regardless.', 'richardmedina-security-hardening' ),
					! empty( $opts['debug_mode'] )
				);
				?>
			</div>
		</div>
		<?php
	}

	private function render_firewall_tab( array $opts ): void {
		?>
		<div class="rm-sh-section">
			<div class="rm-sh-section__head">
				<h3 class="rm-sh-section__title"><?php esc_html_e( 'Mode and inspection', 'richardmedina-security-hardening' ); ?></h3>
				<p class="rm-sh-section__sub"><?php esc_html_e( 'Choose how to react to a match and which request surfaces to scan.', 'richardmedina-security-hardening' ); ?></p>
			</div>
			<div class="rm-sh-section__body">
				<div class="rm-sh-field">
					<label class="rm-sh-field__label" for="rm_sh_mode"><?php esc_html_e( 'Mode', 'richardmedina-security-hardening' ); ?></label>
					<select id="rm_sh_mode" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_mode]">
						<option value="off"     <?php selected( $opts['firewall_mode'], 'off' ); ?>><?php esc_html_e( 'Off', 'richardmedina-security-hardening' ); ?></option>
						<option value="monitor" <?php selected( $opts['firewall_mode'], 'monitor' ); ?>><?php esc_html_e( 'Monitor (log only)', 'richardmedina-security-hardening' ); ?></option>
						<option value="block"   <?php selected( $opts['firewall_mode'], 'block' ); ?>><?php esc_html_e( 'Block (HTTP 403)', 'richardmedina-security-hardening' ); ?></option>
					</select>
					<p class="rm-sh-field__desc"><?php esc_html_e( 'Start in monitor mode for at least 24 hours to catch false positives before switching to block.', 'richardmedina-security-hardening' ); ?></p>
				</div>
				<div class="rm-sh-field">
					<span class="rm-sh-field__label"><?php esc_html_e( 'Inspect', 'richardmedina-security-hardening' ); ?></span>
					<div class="rm-sh-check-group">
						<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_get]" value="1" <?php checked( $opts['firewall_check_get'] ); ?> /> <?php esc_html_e( 'Query string ($_GET)', 'richardmedina-security-hardening' ); ?></label>
						<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_post]" value="1" <?php checked( $opts['firewall_check_post'] ); ?> /> <?php esc_html_e( 'Body ($_POST)', 'richardmedina-security-hardening' ); ?></label>
						<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_cookie]" value="1" <?php checked( $opts['firewall_check_cookie'] ); ?> /> <?php esc_html_e( 'Cookies', 'richardmedina-security-hardening' ); ?></label>
						<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_headers]" value="1" <?php checked( $opts['firewall_check_headers'] ); ?> /> <?php esc_html_e( 'User-Agent + Referer', 'richardmedina-security-hardening' ); ?></label>
					</div>
				</div>
			</div>
		</div>

		<div class="rm-sh-section">
			<div class="rm-sh-section__head">
				<h3 class="rm-sh-section__title"><?php esc_html_e( 'Allowlists', 'richardmedina-security-hardening' ); ?></h3>
				<p class="rm-sh-section__sub"><?php esc_html_e( 'Skip inspection for trusted sources or known-safe parameter names.', 'richardmedina-security-hardening' ); ?></p>
			</div>
			<div class="rm-sh-section__body">
				<div class="rm-sh-field">
					<label class="rm-sh-field__label" for="rm_sh_ip_allow"><?php esc_html_e( 'IP allowlist', 'richardmedina-security-hardening' ); ?></label>
					<textarea id="rm_sh_ip_allow" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_ip_allowlist]" rows="3"><?php echo esc_textarea( $opts['firewall_ip_allowlist'] ); ?></textarea>
					<p class="rm-sh-field__desc"><?php esc_html_e( 'One IP per line. Requests from these IPs skip inspection.', 'richardmedina-security-hardening' ); ?></p>
				</div>
				<div class="rm-sh-field">
					<label class="rm-sh-field__label" for="rm_sh_url_allow"><?php esc_html_e( 'URL allowlist', 'richardmedina-security-hardening' ); ?></label>
					<textarea id="rm_sh_url_allow" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_url_allowlist]" rows="3"><?php echo esc_textarea( $opts['firewall_url_allowlist'] ); ?></textarea>
					<p class="rm-sh-field__desc"><?php esc_html_e( 'One path or substring per line. Matching request URIs skip inspection.', 'richardmedina-security-hardening' ); ?></p>
				</div>
				<div class="rm-sh-field">
					<label class="rm-sh-field__label" for="rm_sh_param_allow"><?php esc_html_e( 'Parameter allowlist', 'richardmedina-security-hardening' ); ?></label>
					<textarea id="rm_sh_param_allow" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_param_allowlist]" rows="2"><?php echo esc_textarea( $opts['firewall_param_allowlist'] ); ?></textarea>
					<p class="rm-sh-field__desc"><?php esc_html_e( 'Comma- or newline-separated parameter names that are exempt (e.g. rich text editor fields).', 'richardmedina-security-hardening' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}

	private function render_hardening_tab( array $opts ): void {
		$rows = [
			'harden_disable_xmlrpc'         => [
				'label' => __( 'Disable XML-RPC and remove X-Pingback header', 'richardmedina-security-hardening' ),
			],
			'harden_block_php_uploads'      => [
				'label'       => __( 'Block PHP execution in uploads/ via .htaccess', 'richardmedina-security-hardening' ),
				'description' => __( 'Apache only — nginx hosts must add an equivalent location block in their server config.', 'richardmedina-security-hardening' ),
			],
			'harden_block_user_enum'        => [
				'label' => __( 'Block ?author= user enumeration on the front end', 'richardmedina-security-hardening' ),
			],
			'harden_disable_rest_users'     => [
				'label'       => __( 'Hide /wp/v2/users REST endpoint for unauthenticated requests', 'richardmedina-security-hardening' ),
				'description' => __( 'Logged-in requests still see the endpoint, so the block editor user picker keeps working.', 'richardmedina-security-hardening' ),
			],
			'harden_remove_generator'       => [
				'label' => __( 'Remove WordPress generator meta tag', 'richardmedina-security-hardening' ),
			],
			'harden_disable_file_edit'      => [
				'label' => __( 'Show warning if DISALLOW_FILE_EDIT is not set in wp-config.php', 'richardmedina-security-hardening' ),
			],
			'harden_disable_app_passwords'  => [
				'label'       => __( 'Disable application passwords', 'richardmedina-security-hardening' ),
				'description' => __( 'Breaks the WP mobile app, Jetpack, and most headless / API integrations.', 'richardmedina-security-hardening' ),
			],
			'harden_disable_plugin_install' => [
				'label'       => __( 'Disable installing / uploading new plugins (denies install_plugins, upload_plugins)', 'richardmedina-security-hardening' ),
				'description' => __( 'Removes the "Add New" link and blocks the plugin install screen and the zip upload action.', 'richardmedina-security-hardening' ),
			],
			'harden_disable_plugin_edit'    => [
				'label'       => __( 'Disable the in-admin plugin file editor (denies edit_plugins)', 'richardmedina-security-hardening' ),
				'description' => __( 'Blocks Tools → Plugin File Editor without requiring DISALLOW_FILE_EDIT in wp-config.php.', 'richardmedina-security-hardening' ),
			],
			'harden_disable_core_update'    => [
				'label'       => __( 'Disable WordPress core updates (denies update_core)', 'richardmedina-security-hardening' ),
				'description' => __( 'The Updates screen still loads (so plugin/theme updates remain available), but the core upgrade action is blocked with "Sorry, you are not allowed to update this site."', 'richardmedina-security-hardening' ),
			],
			'harden_restrict_rest_external' => [
				'label'       => __( 'Restrict REST API to same-origin / local requests', 'richardmedina-security-hardening' ),
				'description' => __( 'Blocks any REST API request whose Origin/Referer doesn\'t match this site, unless it comes from the local server (127.0.0.1). Logged-in admin block editor still works because it\'s same-origin. Will break the WP mobile app, Jetpack, headless / decoupled frontends on a different domain, and any external integration that hits your REST API.', 'richardmedina-security-hardening' ),
			],
		];

		$groups = [
			'surface' => [
				'title' => __( 'Surface reduction', 'richardmedina-security-hardening' ),
				'sub'   => __( 'Reduce metadata leakage and disable rarely-used surfaces.', 'richardmedina-security-hardening' ),
				'keys'  => [
					'harden_disable_xmlrpc',
					'harden_remove_generator',
					'harden_disable_app_passwords',
				],
			],
			'access' => [
				'title' => __( 'Access control', 'richardmedina-security-hardening' ),
				'sub'   => __( 'Block enumeration, restrict endpoints, contain uploaded code.', 'richardmedina-security-hardening' ),
				'keys'  => [
					'harden_block_php_uploads',
					'harden_block_user_enum',
					'harden_disable_rest_users',
					'harden_disable_file_edit',
				],
			],
			'lockdown' => [
				'title' => __( 'Admin lockdown', 'richardmedina-security-hardening' ),
				'sub'   => __( 'Cap-deny admin actions that touch plugin code or core.', 'richardmedina-security-hardening' ),
				'keys'  => [
					'harden_disable_plugin_install',
					'harden_disable_plugin_edit',
					'harden_disable_core_update',
				],
			],
			'api' => [
				'title' => __( 'API access', 'richardmedina-security-hardening' ),
				'sub'   => __( 'Lock the REST API to same-origin or local requests.', 'richardmedina-security-hardening' ),
				'keys'  => [
					'harden_restrict_rest_external',
				],
			],
		];

		foreach ( $groups as $group ) :
			?>
			<div class="rm-sh-section">
				<div class="rm-sh-section__head">
					<h3 class="rm-sh-section__title"><?php echo esc_html( $group['title'] ); ?></h3>
					<p class="rm-sh-section__sub"><?php echo esc_html( $group['sub'] ); ?></p>
				</div>
				<div class="rm-sh-section__body">
					<?php foreach ( $group['keys'] as $key ) :
						$row = $rows[ $key ];
						$this->render_toggle_row(
							$key,
							$row['label'],
							$row['description'] ?? '',
							! empty( $opts[ $key ] )
						);
					endforeach; ?>
				</div>
			</div>
			<?php
		endforeach;
	}

	private function render_toggle_row( string $key, string $label, string $description, bool $checked ): void {
		$id = 'rm-sh-' . str_replace( '_', '-', $key );
		?>
		<div class="rm-sh-row">
			<div class="rm-sh-row__main">
				<label class="rm-sh-row__label" for="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $label ); ?></label>
				<?php if ( $description !== '' ) : ?>
					<p class="rm-sh-row__desc"><?php echo esc_html( $description ); ?></p>
				<?php endif; ?>
			</div>
			<div class="rm-sh-row__control">
				<label class="rm-sh-switch">
					<input type="checkbox" id="<?php echo esc_attr( $id ); ?>" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( $checked ); ?> />
					<span class="rm-sh-switch__slider" aria-hidden="true"></span>
				</label>
			</div>
		</div>
		<?php
	}

	private function render_hidden_for_inactive_tabs( string $active, array $opts ): void {
		$by_tab = [
			'status'    => [ 'enabled', 'debug_mode' ],
			'firewall'  => [
				'firewall_mode', 'firewall_check_get', 'firewall_check_post',
				'firewall_check_cookie', 'firewall_check_headers',
				'firewall_ip_allowlist', 'firewall_url_allowlist', 'firewall_param_allowlist',
			],
			'hardening' => self::HARDEN_KEYS,
		];

		foreach ( $by_tab as $tab => $keys ) {
			if ( $tab === $active ) {
				continue;
			}
			foreach ( $keys as $key ) {
				$value = $opts[ $key ] ?? '';
				if ( is_bool( $value ) ) {
					if ( $value ) {
						printf(
							'<input type="hidden" name="%s[%s]" value="1" />',
							esc_attr( Settings::OPTION_KEY ),
							esc_attr( $key )
						);
					}
					continue;
				}
				printf(
					'<input type="hidden" name="%s[%s]" value="%s" />',
					esc_attr( Settings::OPTION_KEY ),
					esc_attr( $key ),
					esc_attr( (string) $value )
				);
			}
		}
	}

	private function render_diagnostics(): void {
		$report = get_transient( 'rm_sh_diag_report' );
		?>
		<div class="rm-sh-section">
			<div class="rm-sh-section__head">
				<h3 class="rm-sh-section__title"><?php esc_html_e( 'Diagnostics', 'richardmedina-security-hardening' ); ?></h3>
				<p class="rm-sh-section__sub"><?php esc_html_e( 'Generates a copy-paste-ready report covering plugin, WP, PHP, and current settings.', 'richardmedina-security-hardening' ); ?></p>
			</div>
			<div class="rm-sh-section__body">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rm-sh-diag-actions">
					<?php wp_nonce_field( Diagnostics::NONCE ); ?>
					<input type="hidden" name="action" value="<?php echo esc_attr( Diagnostics::ACTION ); ?>" />
					<?php submit_button( __( 'Run diagnostics', 'richardmedina-security-hardening' ), 'primary', 'submit', false ); ?>
					<?php if ( $report ) : ?>
						<button type="button" class="button rm-sh-copy" data-target="#rm-sh-diag-report"><?php esc_html_e( 'Copy report', 'richardmedina-security-hardening' ); ?></button>
					<?php endif; ?>
				</form>

				<?php if ( $report ) : ?>
					<textarea id="rm-sh-diag-report" class="rm-sh-diag-textarea" readonly rows="24"><?php echo esc_textarea( (string) $report ); ?></textarea>
				<?php else : ?>
					<p class="rm-sh-row__desc"><?php esc_html_e( 'Click "Run diagnostics" to generate a fresh report.', 'richardmedina-security-hardening' ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}

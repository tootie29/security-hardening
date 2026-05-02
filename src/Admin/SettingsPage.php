<?php
declare( strict_types=1 );

namespace RichardMedina\SecurityHardening\Admin;

use RichardMedina\SecurityHardening\Support\Settings;

defined( 'ABSPATH' ) || exit;

final class SettingsPage {

	public const PAGE_SLUG = 'rm-sh-settings';
	public const GROUP     = 'rm_sh_settings_group';

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
			<h1><?php esc_html_e( 'RichardMedina Security Hardening', 'richardmedina-security-hardening' ); ?></h1>

			<?php if ( isset( $_GET['updated'] ) && $_GET['updated'] === 'reset' ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings reset to defaults.', 'richardmedina-security-hardening' ); ?></p></div>
			<?php endif; ?>

			<h2 class="nav-tab-wrapper">
				<?php foreach ( $tabs as $key => $label ) :
					$url = add_query_arg( [ 'page' => self::PAGE_SLUG, 'tab' => $key ], admin_url( 'options-general.php' ) );
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
					// Persist all settings on every save by rendering hidden inputs for inactive tabs.
					$this->render_hidden_for_inactive_tabs( $active, $opts );

					if ( $active === 'status' ) {
						$this->render_status_tab( $opts );
					} elseif ( $active === 'firewall' ) {
						$this->render_firewall_tab( $opts );
					} elseif ( $active === 'hardening' ) {
						$this->render_hardening_tab( $opts );
					}
					?>

					<?php submit_button(); ?>
				</form>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Reset all RichardMedina Security Hardening settings to defaults?', 'richardmedina-security-hardening' ) ); ?>');">
					<?php wp_nonce_field( 'rm_sh_reset' ); ?>
					<input type="hidden" name="action" value="rm_sh_reset_defaults" />
					<?php submit_button( __( 'Reset to defaults', 'richardmedina-security-hardening' ), 'delete', 'submit', false ); ?>
				</form>
			<?php endif; ?>

			<p class="rm-sh-version">
				<?php echo esc_html( sprintf( __( 'RichardMedina Security Hardening v%s', 'richardmedina-security-hardening' ), RM_SH_VERSION ) ); ?>
			</p>
		</div>
		<?php
	}

	private function render_status_tab( array $opts ): void {
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Master switch', 'richardmedina-security-hardening' ); ?></th>
				<td>
					<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[enabled]" value="1" <?php checked( $opts['enabled'] ); ?> />
					<?php esc_html_e( 'Enable RichardMedina Security Hardening', 'richardmedina-security-hardening' ); ?></label>
					<p class="description"><?php esc_html_e( 'When off, the firewall and hardening features are inactive. The settings page remains available.', 'richardmedina-security-hardening' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Debug mode', 'richardmedina-security-hardening' ); ?></th>
				<td>
					<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[debug_mode]" value="1" <?php checked( $opts['debug_mode'] ); ?> />
					<?php esc_html_e( 'Verbose logging to uploads/rm-sh-logs/', 'richardmedina-security-hardening' ); ?></label>
				</td>
			</tr>
		</table>
		<?php
	}

	private function render_firewall_tab( array $opts ): void {
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Mode', 'richardmedina-security-hardening' ); ?></th>
				<td>
					<select name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_mode]">
						<option value="off"     <?php selected( $opts['firewall_mode'], 'off' ); ?>><?php esc_html_e( 'Off', 'richardmedina-security-hardening' ); ?></option>
						<option value="monitor" <?php selected( $opts['firewall_mode'], 'monitor' ); ?>><?php esc_html_e( 'Monitor (log only)', 'richardmedina-security-hardening' ); ?></option>
						<option value="block"   <?php selected( $opts['firewall_mode'], 'block' ); ?>><?php esc_html_e( 'Block (403)', 'richardmedina-security-hardening' ); ?></option>
					</select>
					<p class="description"><?php esc_html_e( 'Start in monitor mode for at least 24 hours to catch false positives before switching to block.', 'richardmedina-security-hardening' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Inspect', 'richardmedina-security-hardening' ); ?></th>
				<td>
					<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_get]" value="1" <?php checked( $opts['firewall_check_get'] ); ?> /> <?php esc_html_e( 'Query string ($_GET)', 'richardmedina-security-hardening' ); ?></label><br>
					<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_post]" value="1" <?php checked( $opts['firewall_check_post'] ); ?> /> <?php esc_html_e( 'Body ($_POST)', 'richardmedina-security-hardening' ); ?></label><br>
					<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_cookie]" value="1" <?php checked( $opts['firewall_check_cookie'] ); ?> /> <?php esc_html_e( 'Cookies', 'richardmedina-security-hardening' ); ?></label><br>
					<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_check_headers]" value="1" <?php checked( $opts['firewall_check_headers'] ); ?> /> <?php esc_html_e( 'User-Agent + Referer', 'richardmedina-security-hardening' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="rm_sh_ip_allow"><?php esc_html_e( 'IP allowlist', 'richardmedina-security-hardening' ); ?></label></th>
				<td>
					<textarea id="rm_sh_ip_allow" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_ip_allowlist]" rows="3" cols="50" class="large-text code"><?php echo esc_textarea( $opts['firewall_ip_allowlist'] ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One IP per line. Requests from these IPs skip inspection.', 'richardmedina-security-hardening' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="rm_sh_url_allow"><?php esc_html_e( 'URL allowlist', 'richardmedina-security-hardening' ); ?></label></th>
				<td>
					<textarea id="rm_sh_url_allow" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_url_allowlist]" rows="3" cols="50" class="large-text code"><?php echo esc_textarea( $opts['firewall_url_allowlist'] ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One path or substring per line. Matching request URIs skip inspection.', 'richardmedina-security-hardening' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="rm_sh_param_allow"><?php esc_html_e( 'Parameter allowlist', 'richardmedina-security-hardening' ); ?></label></th>
				<td>
					<textarea id="rm_sh_param_allow" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[firewall_param_allowlist]" rows="2" cols="50" class="large-text code"><?php echo esc_textarea( $opts['firewall_param_allowlist'] ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Comma- or newline-separated parameter names that are exempt (e.g. rich text editor fields).', 'richardmedina-security-hardening' ); ?></p>
				</td>
			</tr>
		</table>
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
		];
		?>
		<table class="form-table" role="presentation">
			<?php foreach ( $rows as $key => $row ) : ?>
				<tr>
					<th scope="row"><?php echo esc_html( $row['label'] ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( Settings::OPTION_KEY ); ?>[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $opts[ $key ] ) ); ?> />
						<?php esc_html_e( 'Enabled', 'richardmedina-security-hardening' ); ?></label>
						<?php if ( ! empty( $row['description'] ) ) : ?>
							<p class="description"><?php echo esc_html( $row['description'] ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
		</table>
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
			'hardening' => [
				'harden_disable_xmlrpc', 'harden_block_php_uploads',
				'harden_block_user_enum', 'harden_disable_rest_users',
				'harden_remove_generator', 'harden_disable_file_edit',
				'harden_disable_app_passwords',
				'harden_disable_plugin_install', 'harden_disable_plugin_edit',
				'harden_disable_core_update',
			],
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
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( Diagnostics::NONCE ); ?>
			<input type="hidden" name="action" value="<?php echo esc_attr( Diagnostics::ACTION ); ?>" />
			<p>
				<?php submit_button( __( 'Run diagnostics', 'richardmedina-security-hardening' ), 'primary', 'submit', false ); ?>
			</p>
		</form>

		<?php if ( $report ) : ?>
			<h2><?php esc_html_e( 'Diagnostics report', 'richardmedina-security-hardening' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Copy and paste this when reporting an issue.', 'richardmedina-security-hardening' ); ?></p>
			<textarea readonly rows="24" class="large-text code"><?php echo esc_textarea( (string) $report ); ?></textarea>
		<?php endif; ?>
		<?php
	}
}

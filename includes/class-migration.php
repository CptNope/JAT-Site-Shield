<?php
/**
 * One-time move from Anderson Site Shield, this plugin's name before 1.0.
 *
 * Anderson Site Shield stored everything under the "anshield" prefix and
 * derived its two-factor key with a different label, so a straight copy
 * isn't enough: each user's two-factor secret is decrypted with the old key
 * and encrypted again with this plugin's key. Nothing of the old plugin is
 * deleted here; deleting Anderson Site Shield afterwards removes its data.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Moves settings, two-factor enrolment, login sessions and the activity log.
 */
class Migration {

	/** Option recording that the move has been done (or that there was nothing to move). */
	const DONE_OPTION = 'jatss_legacy_migrated';

	/** Old to new option names. Same values, same shape. */
	const OPTIONS = array(
		'anshield_settings'     => 'jatss_settings',
		'anshield_lockouts'     => 'jatss_lockouts',
		'anshield_fim_state'    => 'jatss_fim_state',
		'anshield_fim_last'     => 'jatss_fim_last',
		'anshield_fim_ack'      => 'jatss_fim_ack',
		'anshield_fim_baseline' => 'jatss_fim_baseline',
		'anshield_fim_rebase'   => 'jatss_fim_rebase',
		'anshield_uploads_test' => 'jatss_uploads_test',
	);

	/** User meta copied as is. The secret itself is re-encrypted separately. */
	const USER_META = array(
		'anshield_backup_codes'   => 'jatss_backup_codes',
		'anshield_totp_last_step' => 'jatss_totp_last_step',
		'anshield_seen'           => 'jatss_seen',
	);

	/**
	 * Hook the fallback check for installs that skipped the activation hook
	 * (for example a plugin replaced over SFTP).
	 */
	public static function register() {
		if ( ! get_option( self::DONE_OPTION ) ) {
			add_action( 'admin_init', array( self::class, 'maybe_run_from_admin' ) );
		}
	}

	/**
	 * Run from the dashboard for someone allowed to manage plugins.
	 */
	public static function maybe_run_from_admin() {
		if ( current_user_can( 'activate_plugins' ) ) {
			self::run();
		}
	}

	/**
	 * Whether Anderson Site Shield left anything behind on this site.
	 *
	 * @return bool
	 */
	public static function has_legacy_data() {
		global $wpdb;
		if ( false !== get_option( 'anshield_settings' ) ) {
			return true;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		return (bool) $wpdb->get_var( $wpdb->prepare( "SELECT umeta_id FROM {$wpdb->usermeta} WHERE meta_key = %s LIMIT 1", 'anshield_totp_secret' ) );
	}

	/**
	 * Move everything over, once. Safe to call more than once.
	 *
	 * @return array Counts of what was moved, empty when there was nothing to do.
	 */
	public static function run() {
		if ( get_option( self::DONE_OPTION ) ) {
			return array();
		}
		if ( ! self::has_legacy_data() ) {
			update_option( self::DONE_OPTION, array( 'at' => time(), 'found' => false ), false );
			return array();
		}

		$result = array(
			'options'  => self::move_options(),
			'twofa'    => self::move_two_factor(),
			'sessions' => self::move_sessions(),
			'events'   => self::move_events(),
			'failed'   => self::$failed,
		);
		$result['deactivated'] = self::deactivate_old_plugin();

		update_option( self::DONE_OPTION, array( 'at' => time(), 'found' => true ) + $result, false );
		Settings::flush();

		Event_Log::log(
			'plugin.migrated',
			$result['failed'] ? 'warning' : 'notice',
			sprintf(
				/* translators: 1: number of users, 2: number of activity log entries */
				_n( 'Moved settings, two-factor for %1$d user and %2$d activity log entries from Anderson Site Shield.', 'Moved settings, two-factor for %1$d users and %2$d activity log entries from Anderson Site Shield.', $result['twofa'], 'jat-site-shield' ),
				$result['twofa'],
				$result['events']
			),
			array( 'context' => $result )
		);
		return $result;
	}

	/**
	 * Users whose two-factor secret couldn't be decrypted with the old key.
	 *
	 * @var int[]
	 */
	private static $failed = array();

	/**
	 * Copy options. Settings replace the defaults written on activation;
	 * anything else is copied only when this plugin has no value yet.
	 *
	 * @return int Options copied.
	 */
	private static function move_options() {
		$n = 0;
		foreach ( self::OPTIONS as $old => $new ) {
			$value = get_option( $old, null );
			if ( null === $value ) {
				continue;
			}
			$current = get_option( $new, null );
			$is_default = 'jatss_settings' === $new && ( null === $current || Settings::defaults() == $current ); // phpcs:ignore Universal.Operators.StrictComparisons -- array comparison by value.
			if ( null === $current || $is_default ) {
				update_option( $new, $value, 'jatss_settings' === $new );
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Re-encrypt each enrolled user's secret and copy their backup codes.
	 *
	 * @return int Users moved.
	 */
	private static function move_two_factor() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", 'anshield_totp_secret' ) );
		$n    = 0;
		foreach ( (array) $rows as $row ) {
			$uid = (int) $row->user_id;
			if ( get_user_meta( $uid, Modules\Two_Factor::META_SECRET, true ) ) {
				continue; // Already set up in this plugin; leave it alone.
			}
			$plain = self::legacy_decrypt( maybe_unserialize( $row->meta_value ) );
			if ( false === $plain || '' === $plain ) {
				self::$failed[] = $uid;
				continue;
			}
			update_user_meta( $uid, Modules\Two_Factor::META_SECRET, Totp::encrypt( $plain ) );
			foreach ( self::USER_META as $old => $new ) {
				$value = get_user_meta( $uid, $old, true );
				if ( '' !== $value && ! get_user_meta( $uid, $new, true ) ) {
					update_user_meta( $uid, $new, $value );
				}
			}
			++$n;
		}
		return $n;
	}

	/**
	 * Carry the "passed two-factor" mark on existing login sessions, so
	 * people who are logged in now aren't logged out by the switch.
	 *
	 * @return int Sessions updated.
	 */
	private static function move_sessions() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$users = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s", 'session_tokens' ) );
		$n     = 0;
		foreach ( (array) $users as $uid ) {
			$uid      = (int) $uid;
			$sessions = get_user_meta( $uid, 'session_tokens', true );
			if ( ! is_array( $sessions ) ) {
				continue;
			}
			$changed = false;
			foreach ( $sessions as $hash => $info ) {
				if ( is_array( $info ) && ! empty( $info['anshield_2fa'] ) && empty( $info['jatss_2fa'] ) ) {
					$sessions[ $hash ]['jatss_2fa'] = $info['anshield_2fa'];
					$changed                        = true;
					++$n;
				}
			}
			if ( $changed ) {
				update_user_meta( $uid, 'session_tokens', $sessions );
			}
		}
		return $n;
	}

	/**
	 * Copy the activity log into this plugin's table, oldest first.
	 *
	 * @return int Rows copied.
	 */
	private static function move_events() {
		global $wpdb;
		$old = $wpdb->prefix . 'anshield_events';
		$new = Event_Log::table();
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $old ) ) ) !== $old ) {
			return 0;
		}
		Event_Log::install();
		if ( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$new}" ) > 0 ) {
			return 0; // This plugin already has its own log; don't mix the two.
		}
		$cols = 'created_at, event_type, severity, user_id, username, ip, user_agent, object_type, object_id, message, context';
		$done = $wpdb->query( "INSERT INTO {$new} ({$cols}) SELECT {$cols} FROM {$old} ORDER BY id ASC" );
		// phpcs:enable
		return $done ? (int) $done : 0;
	}

	/**
	 * Decrypt a secret stored by Anderson Site Shield.
	 *
	 * @param string $stored Stored value ("v2:" with the dedicated key, "v1:" with the salts).
	 * @return string|false
	 */
	public static function legacy_decrypt( $stored ) {
		if ( ! is_string( $stored ) || strlen( $stored ) < 4 || ! function_exists( 'sodium_crypto_secretbox_open' ) ) {
			return false;
		}
		$prefix = substr( $stored, 0, 3 );
		if ( 'v2:' === $prefix ) {
			$key = self::legacy_key();
		} elseif ( 'v1:' === $prefix ) {
			$key = hash( 'sha256', 'anshield-2fa|' . wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), true );
		} else {
			return false;
		}
		if ( ! $key ) {
			return false;
		}
		$raw = base64_decode( substr( $stored, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return false;
		}
		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return sodium_crypto_secretbox_open( $box, $nonce, $key );
	}

	/**
	 * Anderson Site Shield's dedicated key: its constant, else its key file.
	 *
	 * @return string|false 32 bytes.
	 */
	private static function legacy_key() {
		if ( defined( 'ANSHIELD_SECRET_KEY' ) && strlen( (string) ANSHIELD_SECRET_KEY ) >= 32 ) {
			return hash( 'sha256', 'anshield-2fa|' . ANSHIELD_SECRET_KEY, true );
		}
		$file = WP_CONTENT_DIR . '/anshield-key.php';
		if ( is_readable( $file ) ) {
			$raw = include $file;
			if ( is_string( $raw ) && strlen( $raw ) >= 40 ) {
				return hash( 'sha256', 'anshield-2fa|' . $raw, true );
			}
		}
		return false;
	}

	/**
	 * Turn off Anderson Site Shield so the two don't run side by side.
	 * Its own deactivation removes its uploads rules and scheduled tasks;
	 * its data stays until it is deleted.
	 *
	 * @return string The old plugin's file, or '' if it wasn't active.
	 */
	private static function deactivate_old_plugin() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( get_plugins() as $file => $data ) {
			if ( 'Anderson Site Shield' === $data['Name'] && is_plugin_active( $file ) ) {
				deactivate_plugins( $file );
				return $file;
			}
		}
		return '';
	}
}

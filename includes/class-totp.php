<?php
/**
 * TOTP (RFC 6238) and secret encryption.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Time-based one-time passwords, compatible with Google Authenticator,
 * 1Password, Authy, Microsoft Authenticator and similar apps.
 */
class Totp {

	const PERIOD = 30;
	const DIGITS = 6;
	const WINDOW = 1; // Accept one step either side for clock drift.

	const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * New random secret, base32 (160 bits).
	 *
	 * @return string
	 */
	public static function new_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Base32 encode (RFC 4648, no padding).
	 *
	 * @param string $bin Binary.
	 * @return string
	 */
	public static function base32_encode( $bin ) {
		$bits = '';
		foreach ( str_split( $bin ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $b32 Base32 text.
	 * @return string|false Binary, or false if invalid.
	 */
	public static function base32_decode( $b32 ) {
		$b32  = strtoupper( preg_replace( '/[\s=]/', '', $b32 ) );
		$bits = '';
		foreach ( str_split( $b32 ) as $char ) {
			$pos = strpos( self::B32, $char );
			if ( false === $pos ) {
				return false;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * Code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step.
	 * @return string
	 */
	public static function code( $secret, $step ) {
		$key = self::base32_decode( $secret );
		if ( false === $key || '' === $key ) {
			return '';
		}
		$msg    = pack( 'N*', 0 ) . pack( 'N*', $step );
		$hash   = hash_hmac( 'sha1', $msg, $key, true );
		$offset = ord( $hash[19] ) & 0x0f;
		$num    = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );
		return str_pad( (string) ( $num % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Current time step.
	 *
	 * @param int|null $time Unix time.
	 * @return int
	 */
	public static function step( $time = null ) {
		return (int) floor( ( null === $time ? time() : $time ) / self::PERIOD );
	}

	/**
	 * Check a code. Steps at or before $last_step are refused so a code
	 * can't be replayed.
	 *
	 * @param string $secret    Base32 secret.
	 * @param string $code      User input.
	 * @param int    $last_step Last accepted step.
	 * @return int|false The matching step, or false.
	 */
	public static function verify( $secret, $code, $last_step = 0 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$now = self::step();
		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			$step = $now + $i;
			if ( $step <= (int) $last_step ) {
				continue;
			}
			if ( hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	/**
	 * The otpauth:// URI authenticator apps scan.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label.
	 * @return string
	 */
	public static function uri( $secret, $account ) {
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === trim( $issuer ) ) {
			$issuer = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );
		return 'otpauth://totp/' . $label . '?' . http_build_query(
			array(
				'secret'    => $secret,
				'issuer'    => $issuer,
				'algorithm' => 'SHA1',
				'digits'    => self::DIGITS,
				'period'    => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
	}

	/**
	 * Network option that holds the generated key. A network option, because
	 * on multisite the users (and their two-factor secrets) are shared by
	 * every site.
	 */
	const KEY_OPTION = 'jatss_secret_key';

	/**
	 * Key file written by versions before 1.1.1. It is only read, to carry
	 * its key over; nothing writes it any more.
	 *
	 * @return string
	 */
	public static function legacy_key_file() {
		return WP_CONTENT_DIR . '/jatss-key.php';
	}

	/**
	 * Read the key from the legacy file without running it.
	 *
	 * @return string|false Raw key, or false.
	 */
	private static function legacy_raw_key() {
		$file = self::legacy_key_file();
		if ( ! is_readable( $file ) ) {
			return false;
		}
		$php = file_get_contents( $file, false, null, 0, 1024 ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( is_string( $php ) && preg_match( "/return '([a-f0-9]{64})';/", $php, $m ) ) {
			return $m[1];
		}
		return false;
	}

	/**
	 * Where the key in use comes from.
	 *
	 * @return string 'constant' | 'database' | 'none'
	 */
	public static function key_source() {
		if ( defined( 'JATSS_SECRET_KEY' ) && strlen( (string) JATSS_SECRET_KEY ) >= 32 ) {
			return 'constant';
		}
		return self::dedicated_key() ? 'database' : 'none';
	}

	/**
	 * Every dedicated key that may have encrypted a stored secret, newest
	 * first: the JATSS_SECRET_KEY constant, the generated key, and the key
	 * file of older versions.
	 *
	 * @return string[] 32-byte keys.
	 */
	private static function key_candidates() {
		$keys = array();
		if ( defined( 'JATSS_SECRET_KEY' ) && strlen( (string) JATSS_SECRET_KEY ) >= 32 ) {
			$keys[] = hash( 'sha256', 'jatss-2fa|' . JATSS_SECRET_KEY, true );
		}
		$raw = get_site_option( self::KEY_OPTION );
		if ( is_string( $raw ) && strlen( $raw ) >= 40 ) {
			$keys[] = hash( 'sha256', 'jatss-2fa|' . $raw, true );
		}
		$legacy = self::legacy_raw_key();
		if ( $legacy ) {
			$keys[] = hash( 'sha256', 'jatss-2fa|' . $legacy, true );
		}
		return array_values( array_unique( $keys ) );
	}

	/**
	 * The key used to encrypt: the JATSS_SECRET_KEY constant if set in
	 * wp-config.php, otherwise a random key generated once and kept in the
	 * database. It is independent of the WordPress salts, so rotating the
	 * salts after an incident does not break two-factor. Defining the
	 * constant keeps the key out of the database, so a database leak alone
	 * doesn't reveal two-factor secrets.
	 *
	 * @param bool $create Generate the key if there is none yet.
	 * @return string|false 32-byte key.
	 */
	public static function dedicated_key( $create = true ) {
		if ( defined( 'JATSS_SECRET_KEY' ) && strlen( (string) JATSS_SECRET_KEY ) >= 32 ) {
			return hash( 'sha256', 'jatss-2fa|' . JATSS_SECRET_KEY, true );
		}
		$raw = get_site_option( self::KEY_OPTION );
		if ( ( ! is_string( $raw ) || strlen( $raw ) < 40 ) && $create ) {
			// Keep the key a site already has from an older version's file, so
			// nobody's two-factor breaks; otherwise make a new one.
			$new = self::legacy_raw_key();
			$new = $new ? $new : bin2hex( random_bytes( 32 ) );
			if ( ! add_site_option( self::KEY_OPTION, $new ) ) {
				wp_cache_delete( 'notoptions', 'options' );
			}
			$raw = get_site_option( self::KEY_OPTION ); // Another request may have won the race.
		}
		if ( is_string( $raw ) && strlen( $raw ) >= 40 ) {
			return hash( 'sha256', 'jatss-2fa|' . $raw, true );
		}
		return false;
	}

	/**
	 * Whether a stored secret should be encrypted again with the current key.
	 *
	 * @param string $stored Stored value.
	 * @return bool
	 */
	public static function needs_rekey( $stored ) {
		$current = self::dedicated_key( false );
		if ( ! $current || ! is_string( $stored ) ) {
			return false;
		}
		if ( 0 === strpos( $stored, 'v1:' ) ) {
			return true;
		}
		return 0 === strpos( $stored, 'v2:' ) && false === self::open_with( $stored, $current );
	}

	/**
	 * Fallback key from the salts (only when no dedicated key can be kept).
	 *
	 * @return string 32 bytes.
	 */
	private static function salt_key() {
		return hash( 'sha256', 'jatss-2fa|' . wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), true );
	}

	/**
	 * Encrypt a secret for storage.
	 *
	 * @param string $plain Secret.
	 * @return string
	 */
	public static function encrypt( $plain ) {
		$key    = self::dedicated_key();
		$prefix = $key ? 'v2:' : 'v1:';
		$key    = $key ? $key : self::salt_key();
		$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return $prefix . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $key ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	/**
	 * Decrypt a stored secret.
	 *
	 * @param string $stored Stored value.
	 * @return string|false
	 */
	public static function decrypt( $stored ) {
		if ( ! is_string( $stored ) || strlen( $stored ) < 4 ) {
			return false;
		}
		$prefix = substr( $stored, 0, 3 );
		if ( 'v2:' === $prefix ) {
			foreach ( self::key_candidates() as $key ) {
				$plain = self::open_with( $stored, $key );
				if ( false !== $plain ) {
					return $plain;
				}
			}
			return false;
		}
		if ( 'v1:' === $prefix ) {
			return self::open_with( $stored, self::salt_key() );
		}
		return false;
	}

	/**
	 * Open a stored secret with one key.
	 *
	 * @param string $stored Stored value, with its prefix.
	 * @param string $key    32-byte key.
	 * @return string|false
	 */
	private static function open_with( $stored, $key ) {
		$raw = base64_decode( substr( $stored, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return false;
		}
		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return sodium_crypto_secretbox_open( $box, $nonce, $key );
	}
}

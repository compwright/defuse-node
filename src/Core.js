import { hkdfSync, pbkdf2Sync, timingSafeEqual } from 'crypto'
import { EnvironmentIsBrokenException } from './Exception/EnvironmentIsBrokenException'

export class Core {
  static get HEADER_VERSION_SIZE () {
    return 4
  }

  static get MINIMUM_CIPHERTEXT_SIZE () {
    return 84
  }

  static get CURRENT_VERSION () {
    return Buffer.from([0xDE, 0xF5, 0x02, 0x00])
  }

  static get CIPHER_METHOD () {
    return 'aes-256-ctr'
  }

  static get BLOCK_BYTE_SIZE () {
    return 16
  }

  static get KEY_BYTE_SIZE () {
    return 32
  }

  static get SALT_BYTE_SIZE () {
    return 32
  }

  static get MAC_BYTE_SIZE () {
    return 32
  }

  static get HASH_FUNCTION_NAME () {
    return 'sha256'
  }

  static get ENCRYPTION_INFO_STRING () {
    return 'DefusePHP|V2|KeyForEncryption'
  }

  static get AUTHENTICATION_INFO_STRING () {
    return 'DefusePHP|V2|KeyForAuthentication'
  }

  static get BUFFER_BYTE_SIZE () {
    return 1048576
  }

  static get LEGACY_CIPHER_METHOD () {
    return 'aes-128-cbc'
  }

  static get LEGACY_BLOCK_BYTE_SIZE () {
    return 16
  }

  static get LEGACY_KEY_BYTE_SIZE () {
    return 16
  }

  static get LEGACY_HASH_FUNCTION_NAME () {
    return 'sha256'
  }

  static get LEGACY_MAC_BYTE_SIZE () {
    return 32
  }

  static get LEGACY_ENCRYPTION_INFO_STRING () {
    return 'DefusePHP|KeyForEncryption'
  }

  static get LEGACY_AUTHENTICATION_INFO_STRING () {
    return 'DefusePHP|KeyForAuthentication'
  }

  /**
   * Computes the HKDF key derivation function specified in
   * http://tools.ietf.org/html/rfc5869.
   *
   * @param string hash   Hash Function
   * @param Buffer|String ikm    Initial Keying Material
   * @param Number length How many bytes?
   * @param Buffer|String info   What sort of key are we deriving?
   * @param Buffer|String salt
   *
   * @return Buffer
   */
  static HKDF (hash, ikm, length, info = '', salt = null) {
    return Buffer.from(hkdfSync(hash, ikm, salt || '', info, length))
  }

  /**
   * Checks if two equal-length strings are the same without leaking
   * information through side channels.
   *
   * @param Buffer expected
   * @param Buffer given
   *
   * @return bool
   */
  static hashEquals (expected, given) {
    return timingSafeEqual(expected, given)
  }

  /**
   * Throws an exception if the condition is false.
   *
   * @param bool condition
   * @param string message
   *
   * @throws EnvironmentIsBrokenException
   */
  static ensureTrue (condition, message) {
    if (!condition) {
      throw new EnvironmentIsBrokenException(message)
    }
  }

  /**
   * Behaves roughly like the function substr() in PHP 7 does.
   *
   * @param Buffer buf
   * @param Number start
   * @param Number length
   *
   * @return Buffer
   */
  static ourSubstr (buf, start, length) {
    if (length < 0) {
      throw new Error('Negative lengths are not supported with ourSubstr.')
    }
    if (start < 0) {
      return buf.subarray(buf.length + start, buf.length + start + length)
    }
    return buf.subarray(start, start + length)
  }

  /**
   * Computes the PBKDF2 password-based key derivation function.
   *
   * The PBKDF2 function is defined in RFC 2898. Test vectors can be found in
   * RFC 6070. This implementation of PBKDF2 was originally created by Taylor
   * Hornby, with improvements from http://www.variations-of-shadow.com/.
   *
   * @param string algorithm  The hash algorithm to use. Recommended: SHA256
   * @param string password   The password.
   * @param string salt       A salt that is unique to the password.
   * @param int    count      Iteration count. Higher is better, but slower. Recommended: At least 1000.
   * @param int    keyLength  The length of the derived key in bytes.
   * @param bool   rawOutput  If true, the key is returned in raw binary format. Hex encoded otherwise.
   *
   * @throws EnvironmentIsBrokenException
   *
   * @return string A keyLength-byte key derived from the password and salt.
   */
  static pbkdf2 (algorithm, password, salt, count, keyLength, rawOutput = false) {
    // Type checks:
    if (typeof algorithm !== 'string') {
      throw new Error(
        'pbkdf2(): algorithm must be a string'
      )
    }
    if (typeof password === 'string') {
      throw new Error(
        'pbkdf2(): password must be a string'
      )
    }
    if (typeof salt === 'string') {
      throw new Error(
        'pbkdf2(): salt must be a string'
      )
    }
    // Coerce strings to integers with no information loss or overflow
    count = parseInt(count)
    keyLength = parseInt(keyLength)

    // Whitelist, or we could end up with people using CRC32.
    const allowed = [
      'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
      'ripemd160', 'ripemd256', 'ripemd320', 'whirlpool'
    ]
    Core.ensureTrue(
      allowed.includes(algorithm.toLowerCase()),
      'Algorithm is not a secure cryptographic hash function.'
    )

    Core.ensureTrue(count > 0 && keyLength > 0, 'Invalid PBKDF2 parameters.')

    // The output length is in NIBBLES (4-bits) if rawOutput is false!
    if (!rawOutput) {
      keyLength = keyLength * 2
    }

    const hash = pbkdf2Sync(password, salt, count, keyLength, algorithm)

    return rawOutput
      ? hash
      : hash.toArray('hex')
  }

  static ord (string) {
    //  discuss at: https://locutus.io/php/ord/
    // original by: Kevin van Zonneveld (https://kvz.io)
    // bugfixed by: Onno Marsman (https://twitter.com/onnomarsman)
    // improved by: Brett Zamir (https://brett-zamir.me)
    //    input by: incidence
    //   example 1: ord('K')
    //   returns 1: 75
    //   example 2: ord('\uD800\uDC00'); // surrogate pair to create a single Unicode character
    //   returns 2: 65536

    const str = string + ''
    const code = str.charCodeAt(0)

    if (code >= 0xD800 && code <= 0xDBFF) {
      // High surrogate (could change last hex to 0xDB7F to treat
      // high private surrogates as single characters)
      const hi = code
      if (str.length === 1) {
        // This is just a high surrogate with no following low surrogate,
        // so we return its value;
        return code
        // we could also throw an error as it is not a complete character,
        // but someone may want to know
      }
      const low = str.charCodeAt(1)
      return (hi - 0xD800) * 0x400 + (low - 0xDC00) + 0x10000
    }
    if (code >= 0xDC00 && code <= 0xDFFF) {
      // Low surrogate
      // This is just a low surrogate with no preceding high surrogate,
      // so we return its value;
      return code
      // we could also throw an error as it is not a complete character,
      // but someone may want to know
    }

    return code
  }

  static chr (codePt) {
    //  discuss at: https://locutus.io/php/chr/
    // original by: Kevin van Zonneveld (https://kvz.io)
    // improved by: Brett Zamir (https://brett-zamir.me)
    //   example 1: chr(75) === 'K'
    //   example 1: chr(65536) === '\uD800\uDC00'
    //   returns 1: true
    //   returns 1: true

    if (codePt > 0xFFFF) {
      // Create a four-byte string (length 2) since this code point is high
      //   enough for the UTF-16 encoding (JavaScript internal use), to
      //   require representation with two surrogates (reserved non-characters
      //   used for building other characters; the first is "high" and the next "low")
      codePt -= 0x10000
      return String.fromCharCode(0xD800 + (codePt >> 10), 0xDC00 + (codePt & 0x3FF))
    }
    return String.fromCharCode(codePt)
  }
}

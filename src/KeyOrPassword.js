import { createHash } from 'crypto'
import { Core } from './Core'
import { Key } from './Key'
import { DerivedKeys } from './DerivedKeys'
import { EnvironmentIsBrokenException } from './Exception/EnvironmentIsBrokenException'

export class KeyOrPassword {
  static get PBKDF2_ITERATIONS () {
    return 100000
  }

  static get SECRET_TYPE_KEY () {
    return 1
  }

  static get SECRET_TYPE_PASSWORD () {
    return 2
  }

  #secretType = 0

  #secret

  /**
   * Initializes an instance of KeyOrPassword from a key.
   *
   * @param Key key
   *
   * @returns KeyOrPassword
   */
  static createFromKey (key) {
    return new KeyOrPassword(KeyOrPassword.SECRET_TYPE_KEY, key)
  }

  /**
   * Initializes an instance of KeyOrPassword from a password.
   *
   * @param String password
   *
   * @return KeyOrPassword
   */
  static createFromPassword (password) {
    return new KeyOrPassword(KeyOrPassword.SECRET_TYPE_PASSWORD, password)
  }

  /**
   * Derives authentication and encryption keys from the secret, using a slow
   * key derivation function if the secret is a password.
   *
   * @param String salt
   *
   * @throws CryptoException
   * @throws EnvironmentIsBrokenException
   *
   * @return DerivedKeys
   */
  deriveKeys (salt) {
    Core.ensureTrue(
      salt.length === Core.SALT_BYTE_SIZE,
      'Bad salt; length = ' + salt.length
    )

    if (this.#secretType === KeyOrPassword.SECRET_TYPE_KEY) {
      Core.ensureTrue(this.#secret instanceof Key)

      const akey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        this.#secret.getRawBytes(),
        Core.KEY_BYTE_SIZE,
        Core.AUTHENTICATION_INFO_STRING,
        salt
      )

      const ekey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        this.#secret.getRawBytes(),
        Core.KEY_BYTE_SIZE,
        Core.ENCRYPTION_INFO_STRING,
        salt
      )

      return new DerivedKeys(akey, ekey)
    }

    if (this.#secretType === KeyOrPassword.SECRET_TYPE_PASSWORD) {
      Core.ensureTrue(typeof this.#secret === 'string')

      /*
       * Our PBKDF2 polyfill is vulnerable to a DoS attack documented in
       * GitHub issue #230. The fix is to pre-hash the password to ensure
       * it is short. We do the prehashing here instead of in pbkdf2() so
       * that pbkdf2() still computes the function as defined by the
       * standard.
       */

      const prehash = createHash(Core.HASH_FUNCTION_NAME).update(this.#secret).digest()

      const prekey = Core.pbkdf2(
        Core.HASH_FUNCTION_NAME,
        prehash,
        salt,
        KeyOrPassword.PBKDF2_ITERATIONS,
        Core.KEY_BYTE_SIZE,
        true
      )

      const akey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        prekey,
        Core.KEY_BYTE_SIZE,
        Core.AUTHENTICATION_INFO_STRING,
        salt
      )

      /* Note the cryptographic re-use of salt here. */
      const ekey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        prekey,
        Core.KEY_BYTE_SIZE,
        Core.ENCRYPTION_INFO_STRING,
        salt
      )

      return new DerivedKeys(akey, ekey)
    }

    throw new EnvironmentIsBrokenException('Bad secret type.')
  }

  /**
   * Constructor for KeyOrPassword.
   *
   * @param Number secretType
   * @param Key|String secret
   */
  constructor (secretType, secret) {
    // The constructor is private, so these should never throw.
    if (secretType === KeyOrPassword.SECRET_TYPE_KEY) {
      Core.ensureTrue(secret instanceof Key)
    } else if (secretType === KeyOrPassword.SECRET_TYPE_PASSWORD) {
      Core.ensureTrue(typeof secret === 'string')
    } else {
      throw new EnvironmentIsBrokenException('Bad secret type.')
    }
    this.#secretType = secretType
    this.#secret = secret
  }
}

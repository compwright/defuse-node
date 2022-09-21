import { Buffer } from 'buffer'
import { randomBytes, createHmac, createCipheriv, createDecipheriv } from 'crypto'
import { Core } from './Core'
import { Key } from './Key'
import { KeyOrPassword } from './KeyOrPassword'
import { RuntimeTests } from './RuntimeTests'
import { BadFormatException } from './Exception/BadFormatException'
import { WrongKeyOrModifiedCiphertextException } from './Exception/WrongKeyOrModifiedCiphertextException'

export class Crypto {
  /**
   * Encrypts a string with a Key.
   *
   * @param string plaintext
   * @param Key    key
   * @param boolean rawBinary
   *
   * @throws EnvironmentIsBrokenException
   * @throws TypeError
   *
   * @returns Buffer|string
   */
  static encrypt (plaintext, key, rawBinary = false) {
    if (typeof plaintext !== 'string') {
      throw new TypeError(
        'String expected for argument 1, ' + (typeof plaintext) + ' given instead.'
      )
    }
    if (!(key instanceof Key)) {
      throw new TypeError(
        'Key expected for argument 2, ' + (typeof key) + ' given instead.'
      )
    }
    if (typeof rawBinary !== 'boolean') {
      throw new TypeError(
        'Boolean expected for argument 3, ' + (typeof rawBinary) + ' given instead.'
      )
    }

    const ciphertext = Crypto.#encryptInternal(
      plaintext,
      KeyOrPassword.createFromKey(key),
      rawBinary
    )

    return rawBinary
      ? ciphertext
      : ciphertext.toString('hex')
  }

  /**
   * Encrypts a string with a password, using a slow key derivation function
   * to make password cracking more expensive.
   *
   * @param string plaintext
   * @param string password
   * @param bool   rawBinary
   *
   * @throws EnvironmentIsBrokenException
   * @throws TypeError
   *
   * @returns Buffer|string
   */
  static encryptWithPassword (plaintext, password, rawBinary = false) {
    if (typeof plaintext !== 'string') {
      throw new TypeError(
        'String expected for argument 1, ' + (typeof plaintext) + ' given instead.'
      )
    }
    if (typeof password !== 'string') {
      throw new TypeError(
        'String expected for argument 2, ' + (typeof password) + ' given instead.'
      )
    }
    if (typeof rawBinary !== 'boolean') {
      throw new TypeError(
        'Boolean expected for argument 3, ' + (typeof rawBinary) + ' given instead.'
      )
    }

    const ciphertext = Crypto.#encryptInternal(
      plaintext,
      KeyOrPassword.createFromPassword(password),
      rawBinary
    )

    return rawBinary
      ? ciphertext
      : ciphertext.toString('hex')
  }

  /**
   * Decrypts a ciphertext to a string with a Key.
   *
   * @param Buffer|string ciphertext
   * @param Key    key
   * @param boolean rawBinary
   *
   * @throws TypeError
   * @throws EnvironmentIsBrokenException
   * @throws WrongKeyOrModifiedCiphertextException
   *
   * @returns string
   */
  static decrypt (ciphertext, key, rawBinary = false) {
    if (rawBinary === false && typeof ciphertext !== 'string') {
      throw new TypeError(
        'String expected for argument 1, ' + (typeof ciphertext) + ' given instead.'
      )
    }
    if (rawBinary === true && !(ciphertext instanceof Buffer)) {
      throw new TypeError(
        'Buffer expected for argument 1, ' + (typeof ciphertext) + ' given instead.'
      )
    }
    if (!(key instanceof Key)) {
      throw new TypeError(
        'Key expected for argument 2, ' + (typeof key) + ' given instead.'
      )
    }
    if (typeof rawBinary !== 'boolean') {
      throw new TypeError(
        'Boolean expected for argument 3, ' + (typeof rawBinary) + ' given instead.'
      )
    }

    return Crypto.#decryptInternal(
      ciphertext,
      KeyOrPassword.createFromKey(key),
      rawBinary
    ).toString()
  }

  /**
   * Decrypts a ciphertext to a string with a password, using a slow key
   * derivation function to make password cracking more expensive.
   *
   * @param Buffer|string ciphertext
   * @param string password
   * @param bool   rawBinary
   *
   * @throws EnvironmentIsBrokenException
   * @throws WrongKeyOrModifiedCiphertextException
   * @throws TypeError
   *
   * @returns string
   */
  static decryptWithPassword (ciphertext, password, rawBinary = false) {
    if (rawBinary === false && typeof ciphertext !== 'string') {
      throw new TypeError(
        'String expected for argument 1, ' + (typeof ciphertext) + ' given instead.'
      )
    }
    if (rawBinary === true && !(ciphertext instanceof Buffer)) {
      throw new TypeError(
        'Buffer expected for argument 1, ' + (typeof ciphertext) + ' given instead.'
      )
    }
    if (typeof password !== 'string') {
      throw new TypeError(
        'String expected for argument 2, ' + (typeof password) + ' given instead.'
      )
    }
    if (typeof rawBinary !== 'boolean') {
      throw new TypeError(
        'Boolean expected for argument 3, ' + (typeof rawBinary) + ' given instead.'
      )
    }
    return Crypto.#decryptInternal(
      ciphertext,
      KeyOrPassword.createFromPassword(password),
      rawBinary
    ).toString()
  }

  /**
   * Encrypts a string with either a key or a password.
   *
   * @param string        plaintext
   * @param KeyOrPassword secret
   * @param bool          rawBinary
   *
   * @returns Buffer
   */
  static #encryptInternal (plaintext, secret, rawBinary) {
    RuntimeTests.runtimeTest()

    const salt = randomBytes(Core.SALT_BYTE_SIZE)
    const keys = secret.deriveKeys(salt)
    const ekey = keys.getEncryptionKey()
    const akey = keys.getAuthenticationKey()
    const iv = randomBytes(Core.BLOCK_BYTE_SIZE)

    const ciphertext = Buffer.concat([
      Core.CURRENT_VERSION,
      salt,
      iv,
      Crypto.plainEncrypt(plaintext, ekey, iv)
    ])
    const auth = createHmac(Core.HASH_FUNCTION_NAME, akey).update(ciphertext).digest()
    return Buffer.concat([ciphertext, auth])
  }

  /**
   * Decrypts a ciphertext to a string with either a key or a password.
   *
   * @param string        ciphertext
   * @param KeyOrPassword secret
   * @param bool          rawBinary
   *
   * @throws EnvironmentIsBrokenException
   * @throws WrongKeyOrModifiedCiphertextException
   *
   * @returns Buffer
   */
  static #decryptInternal (ciphertext, secret, rawBinary) {
    RuntimeTests.runtimeTest()

    if (!rawBinary) {
      try {
        ciphertext = Buffer.from(ciphertext, 'hex')
      } catch (ex) {
        if (ex instanceof BadFormatException) {
          throw new WrongKeyOrModifiedCiphertextException(
            'Ciphertext has invalid hex encoding.'
          )
        }
        throw ex
      }
    }

    if (ciphertext.length < Core.MINIMUM_CIPHERTEXT_SIZE) {
      throw new WrongKeyOrModifiedCiphertextException(
        'Ciphertext is too short.'
      )
    }

    // Get and check the version header.
    const header = Core.ourSubstr(ciphertext, 0, Core.HEADER_VERSION_SIZE)
    if (Buffer.compare(header, Core.CURRENT_VERSION) !== 0) {
      throw new WrongKeyOrModifiedCiphertextException(
        'Bad version header.'
      )
    }

    // Get the salt.
    const salt = Core.ourSubstr(
      ciphertext,
      Core.HEADER_VERSION_SIZE,
      Core.SALT_BYTE_SIZE
    )

    // Get the IV.
    const iv = Core.ourSubstr(
      ciphertext,
      Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE,
      Core.BLOCK_BYTE_SIZE
    )

    // Get the HMAC.
    const hmac = Core.ourSubstr(
      ciphertext,
      ciphertext.length - Core.MAC_BYTE_SIZE,
      Core.MAC_BYTE_SIZE
    )

    // Get the actual encrypted ciphertext.
    const encrypted = Core.ourSubstr(
      ciphertext,
      Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + Core.BLOCK_BYTE_SIZE,
      ciphertext.length - Core.MAC_BYTE_SIZE - Core.SALT_BYTE_SIZE - Core.BLOCK_BYTE_SIZE - Core.HEADER_VERSION_SIZE
    )

    // Derive the separate encryption and authentication keys from the key
    // or password, whichever it is.
    const keys = secret.deriveKeys(salt)

    if (Crypto.#verifyHMAC(hmac, Buffer.concat([header, salt, iv, encrypted]), keys.getAuthenticationKey())) {
      return Crypto.plainDecrypt(encrypted, keys.getEncryptionKey(), iv, Core.CIPHER_METHOD)
    }

    throw new WrongKeyOrModifiedCiphertextException(
      'Integrity check failed.'
    )
  }

  /**
   * Raw unauthenticated encryption (insecure on its own).
   *
   * @param string plaintext
   * @param Buffer key
   * @param Buffer iv
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns Buffer
   */
  static plainEncrypt (plaintext, key, iv) {
    const cipher = createCipheriv(Core.CIPHER_METHOD, key, iv)
    return Buffer.concat([
      cipher.update(plaintext),
      cipher.final()
    ])
  }

  /**
   * Raw unauthenticated decryption (insecure on its own).
   *
   * @param string ciphertext
   * @param Buffer key
   * @param Buffer iv
   * @param string cipherMethod
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns Buffer
   */
  static plainDecrypt (ciphertext, key, iv, cipherMethod) {
    const decipher = createDecipheriv(cipherMethod, key, iv)
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ])
  }

  /**
   * Verifies an HMAC without leaking information through side-channels.
   *
   * @param Buffer expectedHmac
   * @param string message
   * @param Buffer key
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns bool
   */
  static #verifyHMAC (expectedHmac, message, key) {
    const messageHmac = createHmac(Core.HASH_FUNCTION_NAME, key).update(message).digest()
    return Core.hashEquals(messageHmac, expectedHmac)
  }
}

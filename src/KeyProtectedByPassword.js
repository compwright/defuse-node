import { Buffer } from 'buffer'
import { createHash } from 'crypto'
import { Core } from './Core'
import { Crypto } from './Crypto'
import { Encoding } from './Encoding'
import { Key } from './Key'
import { BadFormatException } from './Exception/BadFormatException'
import { WrongKeyOrModifiedCiphertextException } from './Exception/WrongKeyOrModifiedCiphertextException'

export class KeyProtectedByPassword {
  static get PASSWORD_KEY_CURRENT_VERSION () {
    return Buffer.from([0xDE, 0xF1, 0x00, 0x00])
  }

  #encryptedKey = ''

  /**
   * Creates a random key protected by the provided password.
   *
   * @param string password
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns KeyProtectedByPassword
   */
  static createRandomPasswordProtectedKey (password) {
    const innerKey = Key.createNewRandomKey()
    /* The password is hashed as a form of poor-man's domain separation
     * between this use of encryptWithPassword() and other uses of
     * encryptWithPassword() that the user may also be using as part of the
     * same protocol. */
    const encryptedKey = Crypto.encryptWithPassword(
      innerKey.saveToAsciiSafeString(),
      createHash(Core.HASH_FUNCTION_NAME).update(password).digest().toString(),
      true
    )

    return new KeyProtectedByPassword(encryptedKey)
  }

  /**
   * Loads a KeyProtectedByPassword from its encoded form.
   *
   * @param string savedKeyString
   *
   * @throws BadFormatException
   *
   * @returns KeyProtectedByPassword
   */
  static loadFromAsciiSafeString (savedKeyString) {
    const encryptedKey = Encoding.loadBytesFromChecksummedAsciiSafeString(
      KeyProtectedByPassword.PASSWORD_KEY_CURRENT_VERSION,
      savedKeyString
    )
    return new KeyProtectedByPassword(encryptedKey)
  }

  /**
   * Encodes the KeyProtectedByPassword into a string of printable ASCII
   * characters.
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns string
   */
  saveToAsciiSafeString () {
    return Encoding.saveBytesToChecksummedAsciiSafeString(
      KeyProtectedByPassword.PASSWORD_KEY_CURRENT_VERSION,
      this.#encryptedKey
    )
  }

  /**
   * Decrypts the protected key, returning an unprotected Key object that can
   * be used for encryption and decryption.
   *
   * @throws EnvironmentIsBrokenException
   * @throws WrongKeyOrModifiedCiphertextException
   *
   * @param string password
   * @returns Key
   */
  unlockKey (password) {
    try {
      const innerKeyEncoded = Crypto.decryptWithPassword(
        this.#encryptedKey,
        createHash(Core.HASH_FUNCTION_NAME).update(password).digest().toString(),
        true
      )
      return Key.loadFromAsciiSafeString(innerKeyEncoded)
    } catch (ex) {
      if (ex instanceof BadFormatException) {
        /* This should never happen unless an attacker replaced the
         * encrypted key ciphertext with some other ciphertext that was
         * encrypted with the same password. We transform the exception type
         * here in order to make the API simpler, avoiding the need to
         * document that this method might throw an BadFormatException. */
        throw new WrongKeyOrModifiedCiphertextException(
          'The decrypted key was found to be in an invalid format. ' +
                    'This very likely indicates it was modified by an attacker.'
        )
      }
      throw ex
    }
  }

  /**
   * Changes the password.
   *
   * @param string currentPassword
   * @param string newPassword
   *
   * @throws EnvironmentIsBrokenException
   * @throws WrongKeyOrModifiedCiphertextException
   *
   * @returns KeyProtectedByPassword
   */
  changePassword (currentPassword, newPassword) {
    const innerKey = this.unlockKey(currentPassword)
    /* The password is hashed as a form of poor-man's domain separation
     * between this use of encryptWithPassword() and other uses of
     * encryptWithPassword() that the user may also be using as part of the
     * same protocol. */
    const encryptedKey = Crypto.encryptWithPassword(
      innerKey.saveToAsciiSafeString(),
      createHash(Core.HASH_FUNCTION_NAME).update(newPassword).digest().toString(),
      true
    )

    this.#encryptedKey = encryptedKey

    return this
  }

  /**
   * Constructor for KeyProtectedByPassword.
   *
   * @param string encryptedKey
   */
  constructor (encryptedKey) {
    this.#encryptedKey = encryptedKey
  }
}

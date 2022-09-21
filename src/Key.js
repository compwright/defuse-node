import { randomBytes } from 'crypto'
import { Core } from './Core'
import { Encoding } from './Encoding'

export class Key {
  static get KEY_CURRENT_VERSION () {
    return Buffer.from([0xDE, 0xF0, 0x00, 0x00])
  }

  static get KEY_BYTE_SIZE () {
    return 32
  }

  #keyBytes

  /**
   * Creates new random key.
   *
   * @returns Key
   * @throws EnvironmentIsBrokenException
   */
  static createNewRandomKey () {
    return new Key(randomBytes(Key.KEY_BYTE_SIZE))
  }

  /**
   * Loads a Key from its encoded form.
   *
   * By default, this function will call Encoding.trimTrailingWhitespace()
   * to remove trailing CR, LF, NUL, TAB, and SPACE characters, which are
   * commonly appended to files when working with text editors.
   *
   * @param string savedKeyString
   * @param bool doNotTrim (default: false)
   *
   * @throws BadFormatException
   * @throws EnvironmentIsBrokenException
   *
   * @returns Key
   */
  static loadFromAsciiSafeString (savedKeyString, doNotTrim = false) {
    if (!doNotTrim) {
      savedKeyString = Encoding.trimTrailingWhitespace(savedKeyString)
    }
    const keyBytes = Encoding.loadBytesFromChecksummedAsciiSafeString(
      Key.KEY_CURRENT_VERSION,
      savedKeyString
    )
    return new Key(keyBytes)
  }

  /**
   * Encodes the Key into a string of printable ASCII characters.
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns string
   */
  saveToAsciiSafeString () {
    return Encoding.saveBytesToChecksummedAsciiSafeString(
      Key.KEY_CURRENT_VERSION,
      this.#keyBytes
    )
  }

  /**
   * Gets the raw bytes of the key.
   *
   * @returns string
   */
  getRawBytes () {
    return this.#keyBytes
  }

  constructor (bytes) {
    Core.ensureTrue(
      bytes.length === Key.KEY_BYTE_SIZE,
      'Bad key length: ' + bytes.length
    )
    this.#keyBytes = bytes
  }
}

import { Buffer } from 'buffer'
import { createHmac, getCiphers } from 'crypto'
import { Core } from './Core'
import { Crypto } from './Crypto'
import { Key } from './Key'
import { EnvironmentIsBrokenException } from './Exception/EnvironmentIsBrokenException'
import { WrongKeyOrModifiedCiphertextException } from './Exception/WrongKeyOrModifiedCiphertextException'

export class RuntimeTests {
  // 0: Tests haven't been run yet.
  // 1: Tests have passed.
  // 2: Tests are running right now.
  // 3: Tests have failed.
  static #testState = 0

  /**
   * Runs the runtime tests.
   *
   * @throws EnvironmentIsBrokenException
   */
  static runtimeTest () {
    if (RuntimeTests.#testState === 1 || RuntimeTests.#testState === 2) {
      return
    }

    if (RuntimeTests.#testState === 3) {
      /* If an intermittent problem caused a test to fail previously, we
       * want that to be indicated to the user with every call to this
       * library. This way, if the user first does something they really
       * don't care about, and just ignores all exceptions, they won't get
       * screwed when they then start to use the library for something
       * they do care about. */
      throw new EnvironmentIsBrokenException('Tests failed previously.')
    }

    try {
      RuntimeTests.#testState = 2

      if (!getCiphers().includes(Core.CIPHER_METHOD)) {
        throw new EnvironmentIsBrokenException(
          'Cipher method not supported. This is normally caused by an outdated ' +
          'version of OpenSSL (and/or OpenSSL compiled for FIPS compliance). ' +
          'Please upgrade to a newer version of OpenSSL that supports ' +
          Core.CIPHER_METHOD + ' to use this library.'
        )
      }

      RuntimeTests.#AESTestVector()
      RuntimeTests.#HMACTestVector()
      RuntimeTests.#HKDFTestVector()

      RuntimeTests.#testEncryptDecrypt()
      Core.ensureTrue(Key.createNewRandomKey().getRawBytes().length === Core.KEY_BYTE_SIZE)

      Core.ensureTrue(Core.ENCRYPTION_INFO_STRING !== Core.AUTHENTICATION_INFO_STRING)
    } catch (ex) {
      if (ex instanceof EnvironmentIsBrokenException) {
        // Do this, otherwise it will stay in the "tests are running" state.
        RuntimeTests.#testState = 3
      }
      throw ex
    }

    // Change this to '0' make the tests always re-run (for benchmarking).
    RuntimeTests.#testState = 1
  }

  /**
   * High-level tests of Crypto operations.
   *
   * @throws EnvironmentIsBrokenException
   */
  static #testEncryptDecrypt () {
    let key = Key.createNewRandomKey()
    let data = 'EnCrYpT EvErYThInG\x00\x00'

    // Make sure encrypting then decrypting doesn't change the message.
    let ciphertext = Crypto.encrypt(data, key, true)
    let decrypted
    try {
      decrypted = Crypto.decrypt(ciphertext, key, true)
    } catch (ex) {
      if (ex instanceof WrongKeyOrModifiedCiphertextException) {
        // It's important to catch this and change it into a
        // EnvironmentIsBrokenException, otherwise a test failure could trick
        // the user into thinking it's just an invalid ciphertext!
        throw new EnvironmentIsBrokenException()
      }
      throw ex
    }
    Core.ensureTrue(decrypted === data)

    // Modifying the ciphertext: Appending a string.
    try {
      Crypto.decrypt(ciphertext + 'a', key, false)
      throw new EnvironmentIsBrokenException()
    } catch (e) {
      if (e instanceof WrongKeyOrModifiedCiphertextException) {
        /* expected */
      } else {
        throw e
      }
    }

    // Modifying the ciphertext: Changing an HMAC byte.
    const indicesToChange = [
      0, // The header.
      Core.HEADER_VERSION_SIZE + 1, // the salt
      Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + 1, // the IV
      Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + Core.BLOCK_BYTE_SIZE + 1 // the ciphertext
    ]

    for (const index of indicesToChange) {
      try {
        ciphertext[index] = Core.chr((Core.ord(ciphertext[index]) + 1) % 256)
        Crypto.decrypt(ciphertext, key, true)
        throw new EnvironmentIsBrokenException()
      } catch (e) {
        if (e instanceof WrongKeyOrModifiedCiphertextException) {
          /* expected */
        } else {
          throw e
        }
      }
    }

    // Decrypting with the wrong key.
    key = Key.createNewRandomKey()
    data = 'abcdef'
    ciphertext = Crypto.encrypt(data, key, true)
    const wrongKey = Key.createNewRandomKey()
    try {
      Crypto.decrypt(ciphertext, wrongKey, true)
      throw new EnvironmentIsBrokenException()
    } catch (e) {
      if (e instanceof WrongKeyOrModifiedCiphertextException) {
        /* expected */
      } else {
        throw e
      }
    }

    // Ciphertext too small.
    key = Key.createNewRandomKey()
    ciphertext = Buffer.alloc(Core.MINIMUM_CIPHERTEXT_SIZE - 1, 0x61) // A
    try {
      Crypto.decrypt(ciphertext, key, true)
      throw new EnvironmentIsBrokenException()
    } catch (e) {
      if (e instanceof WrongKeyOrModifiedCiphertextException) {
        /* expected */
      } else {
        throw e
      }
    }
  }

  /**
   * Test HKDF against test vectors.
   *
   * @throws EnvironmentIsBrokenException
   */
  static #HKDFTestVector () {
    // HKDF test vectors from RFC 5869

    // Test Case 1
    let ikm = Buffer.alloc(22, 0x0b)
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex')
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')
    let length = 42
    let okm = Buffer.from(
      '3cb25f25faacd57a90434f64d0362f2a' +
      '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
      '34007208d5b887185865',
      'hex'
    )
    let computedOkm = Core.HKDF('sha256', ikm, length, info, salt)
    Core.ensureTrue(Buffer.compare(computedOkm, okm) === 0)

    // Test Case 7
    ikm = Buffer.alloc(22, 0x0c)
    length = 42
    okm = Buffer.from(
      '2c91117204d745f3500d636a62f64f0a' +
      'b3bae548aa53d423b0d1f27ebba6f5e5' +
      '673a081d70cce7acfc48',
      'hex'
    )
    computedOkm = Core.HKDF('sha1', ikm, length, '', null)
    Core.ensureTrue(Buffer.compare(computedOkm, okm) === 0)
  }

  /**
   * Test HMAC against test vectors.
   *
   * @throws EnvironmentIsBrokenException
   */
  static #HMACTestVector () {
    // HMAC test vector From RFC 4231 (Test Case 1)
    const key = '\x0b'.repeat(20)
    const data = 'Hi There'
    const expected = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    const actual = createHmac(Core.HASH_FUNCTION_NAME, key)
      .update(data)
      .digest()
      .toString('hex')
    Core.ensureTrue(actual === expected)
  }

  /**
     * Test AES against test vectors.
     *
     * @throws EnvironmentIsBrokenException
     * @return void
     */
  static #AESTestVector () {
    // AES CTR mode test vector from NIST SP 800-38A
    const key = Buffer.from(
      '603deb1015ca71be2b73aef0857d7781' +
            '1f352c073b6108d72d9810a30914dff4',
      'hex'
    )
    const iv = Buffer.from('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex')
    const expectedPlaintext = Buffer.from(
      '6bc1bee22e409f96e93d7e117393172a' +
            'ae2d8a571e03ac9c9eb76fac45af8e51' +
            '30c81c46a35ce411e5fbc1191a0a52ef' +
            'f69f2445df4f9b17ad2b417be66c3710',
      'hex'
    )
    const expectedCiphertext = Buffer.from(
      '601ec313775789a5b7a7f504bbf3d228' +
            'f443e3ca4d62b59aca84e990cacaf5c5' +
            '2b0930daa23de94ce87017ba2d84988d' +
            'dfc9c58db67aada613c2dd08457941a6',
      'hex'
    )

    const computedCiphertext = Crypto.plainEncrypt(expectedPlaintext, key, iv)
    Core.ensureTrue(Buffer.compare(computedCiphertext, expectedCiphertext) === 0)

    const computedPlaintext = Crypto.plainDecrypt(expectedCiphertext, key, iv, Core.CIPHER_METHOD)
    Core.ensureTrue(Buffer.compare(computedPlaintext, expectedPlaintext) === 0)
  }
}

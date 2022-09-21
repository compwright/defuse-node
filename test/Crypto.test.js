import { describe, expect, test } from '@jest/globals'
import { randomBytes } from 'crypto'
import { Core } from '../src/Core'
import { Crypto } from '../src/Crypto'
import { Key } from '../src/Key'
import { WrongKeyOrModifiedCiphertextException } from '../src/Exception/WrongKeyOrModifiedCiphertextException'
import { EnvironmentIsBrokenException } from '../src/Exception/EnvironmentIsBrokenException'

describe('Crypto', () => {
  // Test for issue #165 -- encrypting then decrypting empty string fails.
  test('empty string', () => {
    const str = ''
    const key = Key.createNewRandomKey()
    const ciphertext = Crypto.encrypt(str, key, false)
    const plaintext = Crypto.decrypt(ciphertext, key, false)
    expect(plaintext).toEqual(str)
  })

  // This mirrors the one in RuntimeTests.php, but for passwords.
  // We can't runtime-test the password stuff because it runs PBKDF2.
  test('encrypt decrypt with password', () => {
    let data = 'EnCrYpT EvErYThInG\x00\x00'
    let password = 'password'

    // Make sure encrypting then decrypting doesn't change the message.
    let ciphertext = Crypto.encryptWithPassword(data, password, true)
    let decrypted
    try {
      decrypted = Crypto.decryptWithPassword(ciphertext, password, true)
    } catch (ex) {
      if (ex instanceof WrongKeyOrModifiedCiphertextException) {
        // It's important to catch this and change it into a
        // EnvironmentIsBrokenException, otherwise a test failure could trick
        // the user into thinking it's just an invalid ciphertext!
        throw new EnvironmentIsBrokenException()
      }
      throw ex
    }
    expect(decrypted).toEqual(data)

    // Modifying the ciphertext: Appending a string.
    expect(() => {
      Crypto.decryptWithPassword(ciphertext + 'a', password, false)
      throw new EnvironmentIsBrokenException()
    }).toThrow(WrongKeyOrModifiedCiphertextException)

    // Modifying the ciphertext: Changing an HMAC byte.
    const indicesToChange = [
      0, // The header.
      Core.HEADER_VERSION_SIZE + 1, // the salt
      Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + 1, // the IV
      Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + Core.BLOCK_BYTE_SIZE + 1 // the ciphertext
    ]

    for (const index of indicesToChange) {
      expect(() => {
        ciphertext[index] = Core.chr((Core.ord(ciphertext[index]) + 1) % 256)
        Crypto.decryptWithPassword(ciphertext, password, true)
        throw new EnvironmentIsBrokenException()
      }).toThrow(WrongKeyOrModifiedCiphertextException)
    }

    // Decrypting with the wrong password.
    password = 'password'
    data = 'abcdef'
    ciphertext = Crypto.encryptWithPassword(data, password, true)
    const wrongPassword = 'wrong_password'
    expect(() => {
      Crypto.decryptWithPassword(ciphertext, wrongPassword, true)
      throw new EnvironmentIsBrokenException()
    }).toThrow(WrongKeyOrModifiedCiphertextException)

    // TypeError; password needs to be a string, not an object
    password = Key.createNewRandomKey()
    expect(() => {
      ciphertext = Crypto.encryptWithPassword(data, password, true)
      throw new Error('Crypto.encryptWithPassword() should not accept key objects')
    }).toThrow(TypeError)

    // Ciphertext too small.
    password = randomBytes(32).toString()
    ciphertext = Buffer.alloc(Core.MINIMUM_CIPHERTEXT_SIZE - 1, 0x61) // A
    expect(() => {
      Crypto.decryptWithPassword(ciphertext, password, true)
      throw new EnvironmentIsBrokenException()
    }).toThrow(WrongKeyOrModifiedCiphertextException)
  })

  test('decrypt raw as hex', () => {
    expect(() => {
      const ciphertext = Crypto.encryptWithPassword('testdata', 'password', true)
      Crypto.decryptWithPassword(ciphertext, 'password', false)
    }).toThrow(TypeError)
  })

  test('decrypt hex as raw', () => {
    expect(() => {
      const ciphertext = Crypto.encryptWithPassword('testdata', 'password', false)
      Crypto.decryptWithPassword(ciphertext, 'password', true)
    }).toThrow(TypeError)
  })

  test('encrypt type error A', () => {
    expect(() => {
      const key = Key.createNewRandomKey()
      Crypto.encrypt(3, key, false)
    }).toThrow(TypeError)
  })

  test('encrypt type error B', () => {
    expect(() => {
      Crypto.encrypt('plaintext', 3, false)
    }).toThrow(TypeError)
  })

  test('encrypt type error C', () => {
    expect(() => {
      const key = Key.createNewRandomKey()
      Crypto.encrypt('plaintext', key, 3)
    }).toThrow(TypeError)
  })

  test('encrypt with password type error A', () => {
    expect(() => {
      Crypto.encryptWithPassword(3, 'password', false)
    }).toThrow(TypeError)
  })

  test('encrypt with password type error B', () => {
    expect(() => {
      Crypto.encryptWithPassword('plaintext', 3, false)
    }).toThrow(TypeError)
  })

  test('encrypt with password type error C', () => {
    expect(() => {
      Crypto.encryptWithPassword('plaintext', 'password', 3)
    }).toThrow(TypeError)
  })

  test('decrypt type error A', () => {
    expect(() => {
      const key = Key.createNewRandomKey()
      Crypto.decrypt(3, key, false)
    }).toThrow(TypeError)
  })

  test('decrypt type error B', () => {
    expect(() => {
      Crypto.decrypt('ciphertext', 3, false)
    }).toThrow(TypeError)
  })

  test('decrypt type error C', () => {
    expect(() => {
      const key = Key.createNewRandomKey()
      Crypto.decrypt('ciphertext', key, 3)
    }).toThrow(TypeError)
  })

  test('decrypt with password type error A', () => {
    expect(() => {
      Crypto.decryptWithPassword(3, 'password', false)
    }).toThrow(TypeError)
  })

  test('decrypt with password type error B', () => {
    expect(() => {
      Crypto.decryptWithPassword('ciphertext', 3, false)
    }).toThrow(TypeError)
  })

  test('decrypt with password type error C', () => {
    expect(() => {
      Crypto.decryptWithPassword('ciphertext', 'password', 3)
    }).toThrow(TypeError)
  })
})

import { describe, expect, test } from '@jest/globals'
import { KeyProtectedByPassword } from '../src/KeyProtectedByPassword'
import { WrongKeyOrModifiedCiphertextException } from '../src/Exception/WrongKeyOrModifiedCiphertextException'
import { BadFormatException } from '../src/Exception/BadFormatException'

describe('Password', () => {
  test('right password', () => {
    const pkey1 = KeyProtectedByPassword.createRandomPasswordProtectedKey('password')
    const pkey2 = KeyProtectedByPassword.loadFromAsciiSafeString(pkey1.saveToAsciiSafeString())

    const key1 = pkey1.unlockKey('password')
    const key2 = pkey2.unlockKey('password')

    expect(key1.getRawBytes()).toEqual(key2.getRawBytes())
  })

  test('wrong password', () => {
    expect(() => {
      const pkey = KeyProtectedByPassword.createRandomPasswordProtectedKey('rightpassword')
      pkey.unlockKey('wrongpassword')
    }).toThrow(WrongKeyOrModifiedCiphertextException)
  })

  test('changed password', () => {
    const pkey1 = KeyProtectedByPassword.createRandomPasswordProtectedKey('password')
    const pkey1EncAscii = pkey1.saveToAsciiSafeString()
    const key1 = pkey1.unlockKey('password').saveToAsciiSafeString()

    pkey1.changePassword('password', 'new password')

    const pkey1EncAsciiNew = pkey1.saveToAsciiSafeString()
    const key1New = pkey1.unlockKey('new password').saveToAsciiSafeString()

    // The encrypted_key should not be the same.
    expect(pkey1EncAscii).not.toEqual(pkey1EncAsciiNew)

    // The actual key should be the same.
    expect(key1).toEqual(key1New)
  })

  test('password actually changes', () => {
    expect(() => {
      const pkey1 = KeyProtectedByPassword.createRandomPasswordProtectedKey('password')
      pkey1.changePassword('password', 'new password')
      pkey1.unlockKey('password')
    }).toThrow(WrongKeyOrModifiedCiphertextException)
  })

  test('malformed load', () => {
    expect(() => {
      const pkey1 = KeyProtectedByPassword.createRandomPasswordProtectedKey('password')
      let pkey1EncAscii = pkey1.saveToAsciiSafeString()
      pkey1EncAscii = 0xFF + pkey1EncAscii.substring(1)
      KeyProtectedByPassword.loadFromAsciiSafeString(pkey1EncAscii)
    }).toThrow(BadFormatException)
  })
})

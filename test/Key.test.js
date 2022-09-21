import { describe, expect, test } from '@jest/globals'
import { Key } from '../src/Key'
import { BadFormatException } from '../src/Exception/BadFormatException'

describe('Key', () => {
  test('create new random key', () => {
    const key = Key.createNewRandomKey()
    expect(key.getRawBytes()).toHaveLength(32)
  })

  test('save and load key', () => {
    const key1 = Key.createNewRandomKey()
    const key2 = Key.loadFromAsciiSafeString(key1.saveToAsciiSafeString())
    expect(key1.getRawBytes().toString('hex')).toEqual(key2.getRawBytes().toString('hex'))
  })

  test('incorrect header', () => {
    const key = Key.createNewRandomKey()
    const keyParts = key.saveToAsciiSafeString().split('')
    keyParts[0] = 'f'
    expect(() => Key.loadFromAsciiSafeString(keyParts.join('')))
      .toThrow(new BadFormatException('Invalid header.'))
  })
})

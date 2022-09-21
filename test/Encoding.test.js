import { describe, expect, test } from '@jest/globals'
import { randomInt, randomBytes } from 'crypto'
import { Encoding } from '../src/Encoding'
import { Core } from '../src/Core'
import { BadFormatException } from '../src/Exception/BadFormatException'

describe('Encoding', () => {
  test('incorrect checksum', () => {
    const header = randomBytes(Core.HEADER_VERSION_SIZE)
    const strParts = Encoding.saveBytesToChecksummedAsciiSafeString(
      header,
      randomBytes(Core.KEY_BYTE_SIZE)
    ).split('')
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 0] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 1] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 3] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 4] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 5] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 6] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 7] = 'f'
    strParts[2 * Encoding.SERIALIZE_HEADER_BYTES + 8] = 'f'
    expect(() => Encoding.loadBytesFromChecksummedAsciiSafeString(header, strParts.join('')))
      .toThrow(new BadFormatException("Data is corrupted, the checksum doesn't match."))
  })

  test('bad hex encoding', () => {
    const header = randomBytes(Core.HEADER_VERSION_SIZE)
    const strParts = Encoding.saveBytesToChecksummedAsciiSafeString(
      header,
      randomBytes(Core.KEY_BYTE_SIZE)
    ).split('')
    strParts[0] = 0x5A // Z
    expect(() => Encoding.loadBytesFromChecksummedAsciiSafeString(header, strParts.join('')))
      .toThrow(new BadFormatException('Invalid header.'))
  })

  test('padded hex encoding', () => {
    /* We're just ensuring that an empty string doesn't produce an error. */
    expect(Encoding.trimTrailingWhitespace('')).toEqual('')

    const header = randomBytes(Core.HEADER_VERSION_SIZE)
    let str = Encoding.saveBytesToChecksummedAsciiSafeString(
      header,
      randomBytes(Core.KEY_BYTE_SIZE)
    )
    const orig = str
    const noise = ['\r', '\n', '\t', '\0']
    for (let i = 0; i < 1000; ++i) {
      const c = noise[randomInt(0, 3)]
      str += c
      expect(Encoding.trimTrailingWhitespace(str)).toEqual(orig)
    }
  })
})

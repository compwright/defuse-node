import { Core } from './Core'
import { BadFormatException } from './Exception/BadFormatException'
import { createHash } from 'crypto'

export class Encoding {
  static get CHECKSUM_BYTE_SIZE () {
    return 32
  }

  static get CHECKSUM_HASH_ALGO () {
    return 'sha256'
  }

  static get SERIALIZE_HEADER_BYTES () {
    return 4
  }

  /**
   * Remove trailing whitespace without table look-ups or branches.
   *
   * Calling this function may leak the length of the string as well as the
   * number of trailing whitespace characters through side-channels.
   *
   * @param string str
   * @returns string
   */
  static trimTrailingWhitespace (str) {
    let length = str.length
    if (length < 1) {
      return ''
    }

    const strParts = str.split('')
    let prevLength
    do {
      prevLength = length
      let last = length - 1
      let chr = Core.ord(strParts[last])

      /* Null Byte (0x00), a.k.a. \0 */
      // if (chr === 0x00) length -= 1;
      let sub = ((chr - 1) >> 8) & 1
      length -= sub
      last -= sub

      /* Horizontal Tab (0x09) a.k.a. \t */
      chr = Core.ord(strParts[last])
      // if (chr === 0x09) length -= 1;
      sub = (((0x08 - chr) & (chr - 0x0a)) >> 8) & 1
      length -= sub
      last -= sub

      /* New Line (0x0a), a.k.a. \n */
      chr = Core.ord(strParts[last])
      // if (chr === 0x0a) length -= 1;
      sub = (((0x09 - chr) & (chr - 0x0b)) >> 8) & 1
      length -= sub
      last -= sub

      /* Carriage Return (0x0D), a.k.a. \r */
      chr = Core.ord(strParts[last])
      // if (chr === 0x0d) length -= 1;
      sub = (((0x0c - chr) & (chr - 0x0e)) >> 8) & 1
      length -= sub
      last -= sub

      /* Space */
      chr = Core.ord(strParts[last])
      // if (chr === 0x20) length -= 1;
      sub = (((0x1f - chr) & (chr - 0x21)) >> 8) & 1
      length -= sub
    } while (prevLength !== length && length > 0)
    return strParts.join('').substring(0, length)
  }

  /*
   * SECURITY NOTE ON APPLYING CHECKSUMS TO SECRETS:
   *
   *      The checksum introduces a potential security weakness. For example,
   *      suppose we apply a checksum to a key, and that an adversary has an
   *      exploit against the process containing the key, such that they can
   *      overwrite an arbitrary byte of memory and then cause the checksum to
   *      be verified and learn the result.
   *
   *      In this scenario, the adversary can extract the key one byte at
   *      a time by overwriting it with their guess of its value and then
   *      asking if the checksum matches. If it does, their guess was right.
   *      This kind of attack may be more easy to implement and more reliable
   *      than a remote code execution attack.
   *
   *      This attack also applies to authenticated encryption as a whole, in
   *      the situation where the adversary can overwrite a byte of the key
   *      and then cause a valid ciphertext to be decrypted, and then
   *      determine whether the MAC check passed or failed.
   *
   *      By using the full SHA256 hash instead of truncating it, I'm ensuring
   *      that both ways of going about the attack are equivalently difficult.
   *      A shorter checksum of say 32 bits might be more useful to the
   *      adversary as an oracle in case their writes are coarser grained.
   *
   *      Because the scenario assumes a serious vulnerability, we don't try
   *      to prevent attacks of this style.
   */

  /**
   * INTERNAL USE ONLY: Applies a version header, applies a checksum, and
   * then encodes a byte string into a range of printable ASCII characters.
   *
   * @param Buffer header
   * @param Buffer bytes
   *
   * @throws EnvironmentIsBrokenException
   *
   * @returns string
   */
  static saveBytesToChecksummedAsciiSafeString (header, bytes) {
    // Headers must be a constant length to prevent one type's header from
    // being a prefix of another type's header, leading to ambiguity.
    Core.ensureTrue(
      header.length === Encoding.SERIALIZE_HEADER_BYTES,
      'Header must be ' + Encoding.SERIALIZE_HEADER_BYTES + ' bytes.'
    )

    const message = Buffer.concat([header, bytes])

    const checksum = createHash(Encoding.CHECKSUM_HASH_ALGO)
      .update(message)
      .digest()

    return Buffer.concat([message, checksum])
      .toString('hex')
  }

  /**
   * INTERNAL USE ONLY: Decodes, verifies the header and checksum, and returns
   * the encoded byte string.
   *
   * @param Buffer expectedHeader
   * @param String str
   *
   * @throws EnvironmentIsBrokenException
   * @throws BadFormatException
   *
   * @returns Buffer
   */
  static loadBytesFromChecksummedAsciiSafeString (expectedHeader, str) {
    // Headers must be a constant length to prevent one type's header from
    // being a prefix of another type's header, leading to ambiguity.
    Core.ensureTrue(
      expectedHeader.length === Encoding.SERIALIZE_HEADER_BYTES,
      'Header must be ' + Encoding.SERIALIZE_HEADER_BYTES + ' bytes.'
    )

    /* If you get an exception here when attempting to load from a file, first pass your
        key to Encoding.trimTrailingWhitespace() to remove newline characters, etc.      */
    const bytes = Buffer.from(str, 'hex')

    /* Make sure we have enough bytes to get the version header and checksum. */
    if (bytes.length < Encoding.SERIALIZE_HEADER_BYTES + Encoding.CHECKSUM_BYTE_SIZE) {
      throw new BadFormatException(
        'Encoded data is shorter than expected.'
      )
    }

    /* Grab the version header. */
    const actualHeader = bytes.subarray(0, Encoding.SERIALIZE_HEADER_BYTES)

    if (Buffer.compare(actualHeader, expectedHeader) !== 0) {
      throw new BadFormatException(
        'Invalid header.'
      )
    }

    /* Grab the bytes that are checksummed. */
    const checkedBytes = bytes.subarray(
      0,
      bytes.length - Encoding.CHECKSUM_BYTE_SIZE
    )

    /* Grab the included checksum. */
    const checksumA = bytes.subarray(
      bytes.length - Encoding.CHECKSUM_BYTE_SIZE
    )

    /* Re-compute the checksum. */
    const checksumB = createHash(Encoding.CHECKSUM_HASH_ALGO)
      .update(checkedBytes)
      .digest()

    /* Check if the checksum matches. */
    if (Buffer.compare(checksumA, checksumB) !== 0) {
      throw new BadFormatException(
        "Data is corrupted, the checksum doesn't match."
      )
    }

    return bytes.subarray(
      Encoding.SERIALIZE_HEADER_BYTES,
      bytes.length - Encoding.CHECKSUM_BYTE_SIZE
    )
  }
}

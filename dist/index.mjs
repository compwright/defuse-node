import { Buffer as Buffer$1 } from 'buffer';
import { hkdfSync, timingSafeEqual, pbkdf2Sync, createHash, randomBytes, getCiphers, createHmac, createCipheriv, createDecipheriv } from 'crypto';

class BadFormatException extends Error {
}

class CryptoException extends Error {
}

class EnvironmentIsBrokenException extends Error {
}

class WrongKeyOrModifiedCiphertextException extends Error {
}

const index = {
  __proto__: null,
  BadFormatException: BadFormatException,
  CryptoException: CryptoException,
  EnvironmentIsBrokenException: EnvironmentIsBrokenException,
  WrongKeyOrModifiedCiphertextException: WrongKeyOrModifiedCiphertextException
};

class Core {
  static get HEADER_VERSION_SIZE() {
    return 4;
  }
  static get MINIMUM_CIPHERTEXT_SIZE() {
    return 84;
  }
  static get CURRENT_VERSION() {
    return Buffer.from([222, 245, 2, 0]);
  }
  static get CIPHER_METHOD() {
    return "aes-256-ctr";
  }
  static get BLOCK_BYTE_SIZE() {
    return 16;
  }
  static get KEY_BYTE_SIZE() {
    return 32;
  }
  static get SALT_BYTE_SIZE() {
    return 32;
  }
  static get MAC_BYTE_SIZE() {
    return 32;
  }
  static get HASH_FUNCTION_NAME() {
    return "sha256";
  }
  static get ENCRYPTION_INFO_STRING() {
    return "DefusePHP|V2|KeyForEncryption";
  }
  static get AUTHENTICATION_INFO_STRING() {
    return "DefusePHP|V2|KeyForAuthentication";
  }
  static get BUFFER_BYTE_SIZE() {
    return 1048576;
  }
  static get LEGACY_CIPHER_METHOD() {
    return "aes-128-cbc";
  }
  static get LEGACY_BLOCK_BYTE_SIZE() {
    return 16;
  }
  static get LEGACY_KEY_BYTE_SIZE() {
    return 16;
  }
  static get LEGACY_HASH_FUNCTION_NAME() {
    return "sha256";
  }
  static get LEGACY_MAC_BYTE_SIZE() {
    return 32;
  }
  static get LEGACY_ENCRYPTION_INFO_STRING() {
    return "DefusePHP|KeyForEncryption";
  }
  static get LEGACY_AUTHENTICATION_INFO_STRING() {
    return "DefusePHP|KeyForAuthentication";
  }
  static HKDF(hash, ikm, length, info = "", salt = null) {
    return Buffer.from(hkdfSync(hash, ikm, salt || "", info, length));
  }
  static hashEquals(expected, given) {
    return timingSafeEqual(expected, given);
  }
  static ensureTrue(condition, message) {
    if (!condition) {
      throw new EnvironmentIsBrokenException(message);
    }
  }
  static ourSubstr(buf, start, length) {
    if (length < 0) {
      throw new Error("Negative lengths are not supported with ourSubstr.");
    }
    if (start < 0) {
      return buf.subarray(buf.length + start, buf.length + start + length);
    }
    return buf.subarray(start, start + length);
  }
  static pbkdf2(algorithm, password, salt, count, keyLength, rawOutput = false) {
    if (typeof algorithm !== "string") {
      throw new Error(
        "pbkdf2(): algorithm must be a string"
      );
    }
    if (typeof password === "string") {
      throw new Error(
        "pbkdf2(): password must be a string"
      );
    }
    if (typeof salt === "string") {
      throw new Error(
        "pbkdf2(): salt must be a string"
      );
    }
    count = parseInt(count);
    keyLength = parseInt(keyLength);
    const allowed = [
      "sha1",
      "sha224",
      "sha256",
      "sha384",
      "sha512",
      "ripemd160",
      "ripemd256",
      "ripemd320",
      "whirlpool"
    ];
    Core.ensureTrue(
      allowed.includes(algorithm.toLowerCase()),
      "Algorithm is not a secure cryptographic hash function."
    );
    Core.ensureTrue(count > 0 && keyLength > 0, "Invalid PBKDF2 parameters.");
    if (!rawOutput) {
      keyLength = keyLength * 2;
    }
    const hash = pbkdf2Sync(password, salt, count, keyLength, algorithm);
    return rawOutput ? hash : hash.toArray("hex");
  }
  static ord(string) {
    const str = string + "";
    const code = str.charCodeAt(0);
    if (code >= 55296 && code <= 56319) {
      const hi = code;
      if (str.length === 1) {
        return code;
      }
      const low = str.charCodeAt(1);
      return (hi - 55296) * 1024 + (low - 56320) + 65536;
    }
    if (code >= 56320 && code <= 57343) {
      return code;
    }
    return code;
  }
  static chr(codePt) {
    if (codePt > 65535) {
      codePt -= 65536;
      return String.fromCharCode(55296 + (codePt >> 10), 56320 + (codePt & 1023));
    }
    return String.fromCharCode(codePt);
  }
}

class Encoding {
  static get CHECKSUM_BYTE_SIZE() {
    return 32;
  }
  static get CHECKSUM_HASH_ALGO() {
    return "sha256";
  }
  static get SERIALIZE_HEADER_BYTES() {
    return 4;
  }
  static trimTrailingWhitespace(str) {
    let length = str.length;
    if (length < 1) {
      return "";
    }
    const strParts = str.split("");
    let prevLength;
    do {
      prevLength = length;
      let last = length - 1;
      let chr = Core.ord(strParts[last]);
      let sub = chr - 1 >> 8 & 1;
      length -= sub;
      last -= sub;
      chr = Core.ord(strParts[last]);
      sub = (8 - chr & chr - 10) >> 8 & 1;
      length -= sub;
      last -= sub;
      chr = Core.ord(strParts[last]);
      sub = (9 - chr & chr - 11) >> 8 & 1;
      length -= sub;
      last -= sub;
      chr = Core.ord(strParts[last]);
      sub = (12 - chr & chr - 14) >> 8 & 1;
      length -= sub;
      last -= sub;
      chr = Core.ord(strParts[last]);
      sub = (31 - chr & chr - 33) >> 8 & 1;
      length -= sub;
    } while (prevLength !== length && length > 0);
    return strParts.join("").substring(0, length);
  }
  static saveBytesToChecksummedAsciiSafeString(header, bytes) {
    Core.ensureTrue(
      header.length === Encoding.SERIALIZE_HEADER_BYTES,
      "Header must be " + Encoding.SERIALIZE_HEADER_BYTES + " bytes."
    );
    const message = Buffer.concat([header, bytes]);
    const checksum = createHash(Encoding.CHECKSUM_HASH_ALGO).update(message).digest();
    return Buffer.concat([message, checksum]).toString("hex");
  }
  static loadBytesFromChecksummedAsciiSafeString(expectedHeader, str) {
    Core.ensureTrue(
      expectedHeader.length === Encoding.SERIALIZE_HEADER_BYTES,
      "Header must be " + Encoding.SERIALIZE_HEADER_BYTES + " bytes."
    );
    const bytes = Buffer.from(str, "hex");
    if (bytes.length < Encoding.SERIALIZE_HEADER_BYTES + Encoding.CHECKSUM_BYTE_SIZE) {
      throw new BadFormatException(
        "Encoded data is shorter than expected."
      );
    }
    const actualHeader = bytes.subarray(0, Encoding.SERIALIZE_HEADER_BYTES);
    if (Buffer.compare(actualHeader, expectedHeader) !== 0) {
      throw new BadFormatException(
        "Invalid header."
      );
    }
    const checkedBytes = bytes.subarray(
      0,
      bytes.length - Encoding.CHECKSUM_BYTE_SIZE
    );
    const checksumA = bytes.subarray(
      bytes.length - Encoding.CHECKSUM_BYTE_SIZE
    );
    const checksumB = createHash(Encoding.CHECKSUM_HASH_ALGO).update(checkedBytes).digest();
    if (Buffer.compare(checksumA, checksumB) !== 0) {
      throw new BadFormatException(
        "Data is corrupted, the checksum doesn't match."
      );
    }
    return bytes.subarray(
      Encoding.SERIALIZE_HEADER_BYTES,
      bytes.length - Encoding.CHECKSUM_BYTE_SIZE
    );
  }
}

var __accessCheck$5 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet$4 = (obj, member, getter) => {
  __accessCheck$5(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd$5 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet$4 = (obj, member, value, setter) => {
  __accessCheck$5(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var _keyBytes;
const _Key = class {
  constructor(bytes) {
    __privateAdd$5(this, _keyBytes, void 0);
    Core.ensureTrue(
      bytes.length === _Key.KEY_BYTE_SIZE,
      "Bad key length: " + bytes.length
    );
    __privateSet$4(this, _keyBytes, bytes);
  }
  static get KEY_CURRENT_VERSION() {
    return Buffer.from([222, 240, 0, 0]);
  }
  static get KEY_BYTE_SIZE() {
    return 32;
  }
  static createNewRandomKey() {
    return new _Key(randomBytes(_Key.KEY_BYTE_SIZE));
  }
  static loadFromAsciiSafeString(savedKeyString, doNotTrim = false) {
    if (!doNotTrim) {
      savedKeyString = Encoding.trimTrailingWhitespace(savedKeyString);
    }
    const keyBytes = Encoding.loadBytesFromChecksummedAsciiSafeString(
      _Key.KEY_CURRENT_VERSION,
      savedKeyString
    );
    return new _Key(keyBytes);
  }
  saveToAsciiSafeString() {
    return Encoding.saveBytesToChecksummedAsciiSafeString(
      _Key.KEY_CURRENT_VERSION,
      __privateGet$4(this, _keyBytes)
    );
  }
  getRawBytes() {
    return __privateGet$4(this, _keyBytes);
  }
};
let Key = _Key;
_keyBytes = new WeakMap();

var __accessCheck$4 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet$3 = (obj, member, getter) => {
  __accessCheck$4(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd$4 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet$3 = (obj, member, value, setter) => {
  __accessCheck$4(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var _akey, _ekey;
class DerivedKeys {
  constructor(akey, ekey) {
    __privateAdd$4(this, _akey, "");
    __privateAdd$4(this, _ekey, "");
    __privateSet$3(this, _akey, akey);
    __privateSet$3(this, _ekey, ekey);
  }
  getAuthenticationKey() {
    return __privateGet$3(this, _akey);
  }
  getEncryptionKey() {
    return __privateGet$3(this, _ekey);
  }
}
_akey = new WeakMap();
_ekey = new WeakMap();

var __accessCheck$3 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet$2 = (obj, member, getter) => {
  __accessCheck$3(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd$3 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet$2 = (obj, member, value, setter) => {
  __accessCheck$3(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var _secretType, _secret;
const _KeyOrPassword = class {
  constructor(secretType, secret) {
    __privateAdd$3(this, _secretType, 0);
    __privateAdd$3(this, _secret, void 0);
    if (secretType === _KeyOrPassword.SECRET_TYPE_KEY) {
      Core.ensureTrue(secret instanceof Key);
    } else if (secretType === _KeyOrPassword.SECRET_TYPE_PASSWORD) {
      Core.ensureTrue(typeof secret === "string");
    } else {
      throw new EnvironmentIsBrokenException("Bad secret type.");
    }
    __privateSet$2(this, _secretType, secretType);
    __privateSet$2(this, _secret, secret);
  }
  static get PBKDF2_ITERATIONS() {
    return 1e5;
  }
  static get SECRET_TYPE_KEY() {
    return 1;
  }
  static get SECRET_TYPE_PASSWORD() {
    return 2;
  }
  static createFromKey(key) {
    return new _KeyOrPassword(_KeyOrPassword.SECRET_TYPE_KEY, key);
  }
  static createFromPassword(password) {
    return new _KeyOrPassword(_KeyOrPassword.SECRET_TYPE_PASSWORD, password);
  }
  deriveKeys(salt) {
    Core.ensureTrue(
      salt.length === Core.SALT_BYTE_SIZE,
      "Bad salt; length = " + salt.length
    );
    if (__privateGet$2(this, _secretType) === _KeyOrPassword.SECRET_TYPE_KEY) {
      Core.ensureTrue(__privateGet$2(this, _secret) instanceof Key);
      const akey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        __privateGet$2(this, _secret).getRawBytes(),
        Core.KEY_BYTE_SIZE,
        Core.AUTHENTICATION_INFO_STRING,
        salt
      );
      const ekey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        __privateGet$2(this, _secret).getRawBytes(),
        Core.KEY_BYTE_SIZE,
        Core.ENCRYPTION_INFO_STRING,
        salt
      );
      return new DerivedKeys(akey, ekey);
    }
    if (__privateGet$2(this, _secretType) === _KeyOrPassword.SECRET_TYPE_PASSWORD) {
      Core.ensureTrue(typeof __privateGet$2(this, _secret) === "string");
      const prehash = createHash(Core.HASH_FUNCTION_NAME).update(__privateGet$2(this, _secret)).digest();
      const prekey = Core.pbkdf2(
        Core.HASH_FUNCTION_NAME,
        prehash,
        salt,
        _KeyOrPassword.PBKDF2_ITERATIONS,
        Core.KEY_BYTE_SIZE,
        true
      );
      const akey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        prekey,
        Core.KEY_BYTE_SIZE,
        Core.AUTHENTICATION_INFO_STRING,
        salt
      );
      const ekey = Core.HKDF(
        Core.HASH_FUNCTION_NAME,
        prekey,
        Core.KEY_BYTE_SIZE,
        Core.ENCRYPTION_INFO_STRING,
        salt
      );
      return new DerivedKeys(akey, ekey);
    }
    throw new EnvironmentIsBrokenException("Bad secret type.");
  }
};
let KeyOrPassword = _KeyOrPassword;
_secretType = new WeakMap();
_secret = new WeakMap();

var __accessCheck$2 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet$1 = (obj, member, getter) => {
  __accessCheck$2(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd$2 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet$1 = (obj, member, value, setter) => {
  __accessCheck$2(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var __privateMethod$1 = (obj, member, method) => {
  __accessCheck$2(obj, member, "access private method");
  return method;
};
var _testState, _testEncryptDecrypt, testEncryptDecrypt_fn, _HKDFTestVector, HKDFTestVector_fn, _HMACTestVector, HMACTestVector_fn, _AESTestVector, AESTestVector_fn;
const _RuntimeTests = class {
  static runtimeTest() {
    var _a, _b, _c, _d;
    if (__privateGet$1(_RuntimeTests, _testState) === 1 || __privateGet$1(_RuntimeTests, _testState) === 2) {
      return;
    }
    if (__privateGet$1(_RuntimeTests, _testState) === 3) {
      throw new EnvironmentIsBrokenException("Tests failed previously.");
    }
    try {
      __privateSet$1(_RuntimeTests, _testState, 2);
      if (!getCiphers().includes(Core.CIPHER_METHOD)) {
        throw new EnvironmentIsBrokenException(
          "Cipher method not supported. This is normally caused by an outdated version of OpenSSL (and/or OpenSSL compiled for FIPS compliance). Please upgrade to a newer version of OpenSSL that supports " + Core.CIPHER_METHOD + " to use this library."
        );
      }
      __privateMethod$1(_a = _RuntimeTests, _AESTestVector, AESTestVector_fn).call(_a);
      __privateMethod$1(_b = _RuntimeTests, _HMACTestVector, HMACTestVector_fn).call(_b);
      __privateMethod$1(_c = _RuntimeTests, _HKDFTestVector, HKDFTestVector_fn).call(_c);
      __privateMethod$1(_d = _RuntimeTests, _testEncryptDecrypt, testEncryptDecrypt_fn).call(_d);
      Core.ensureTrue(Key.createNewRandomKey().getRawBytes().length === Core.KEY_BYTE_SIZE);
      Core.ensureTrue(Core.ENCRYPTION_INFO_STRING !== Core.AUTHENTICATION_INFO_STRING);
    } catch (ex) {
      if (ex instanceof EnvironmentIsBrokenException) {
        __privateSet$1(_RuntimeTests, _testState, 3);
      }
      throw ex;
    }
    __privateSet$1(_RuntimeTests, _testState, 1);
  }
};
let RuntimeTests = _RuntimeTests;
_testState = new WeakMap();
_testEncryptDecrypt = new WeakSet();
testEncryptDecrypt_fn = function() {
  let key = Key.createNewRandomKey();
  let data = "EnCrYpT EvErYThInG\0\0";
  let ciphertext = Crypto.encrypt(data, key, true);
  let decrypted;
  try {
    decrypted = Crypto.decrypt(ciphertext, key, true);
  } catch (ex) {
    if (ex instanceof WrongKeyOrModifiedCiphertextException) {
      throw new EnvironmentIsBrokenException();
    }
    throw ex;
  }
  Core.ensureTrue(decrypted === data);
  try {
    Crypto.decrypt(ciphertext + "a", key, false);
    throw new EnvironmentIsBrokenException();
  } catch (e) {
    if (e instanceof WrongKeyOrModifiedCiphertextException) ; else {
      throw e;
    }
  }
  const indicesToChange = [
    0,
    Core.HEADER_VERSION_SIZE + 1,
    Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + 1,
    Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + Core.BLOCK_BYTE_SIZE + 1
  ];
  for (const index of indicesToChange) {
    try {
      ciphertext[index] = Core.chr((Core.ord(ciphertext[index]) + 1) % 256);
      Crypto.decrypt(ciphertext, key, true);
      throw new EnvironmentIsBrokenException();
    } catch (e) {
      if (e instanceof WrongKeyOrModifiedCiphertextException) ; else {
        throw e;
      }
    }
  }
  key = Key.createNewRandomKey();
  data = "abcdef";
  ciphertext = Crypto.encrypt(data, key, true);
  const wrongKey = Key.createNewRandomKey();
  try {
    Crypto.decrypt(ciphertext, wrongKey, true);
    throw new EnvironmentIsBrokenException();
  } catch (e) {
    if (e instanceof WrongKeyOrModifiedCiphertextException) ; else {
      throw e;
    }
  }
  key = Key.createNewRandomKey();
  ciphertext = Buffer$1.alloc(Core.MINIMUM_CIPHERTEXT_SIZE - 1, 97);
  try {
    Crypto.decrypt(ciphertext, key, true);
    throw new EnvironmentIsBrokenException();
  } catch (e) {
    if (e instanceof WrongKeyOrModifiedCiphertextException) ; else {
      throw e;
    }
  }
};
_HKDFTestVector = new WeakSet();
HKDFTestVector_fn = function() {
  let ikm = Buffer$1.alloc(22, 11);
  const salt = Buffer$1.from("000102030405060708090a0b0c", "hex");
  const info = Buffer$1.from("f0f1f2f3f4f5f6f7f8f9", "hex");
  let length = 42;
  let okm = Buffer$1.from(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    "hex"
  );
  let computedOkm = Core.HKDF("sha256", ikm, length, info, salt);
  Core.ensureTrue(Buffer$1.compare(computedOkm, okm) === 0);
  ikm = Buffer$1.alloc(22, 12);
  length = 42;
  okm = Buffer$1.from(
    "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
    "hex"
  );
  computedOkm = Core.HKDF("sha1", ikm, length, "", null);
  Core.ensureTrue(Buffer$1.compare(computedOkm, okm) === 0);
};
_HMACTestVector = new WeakSet();
HMACTestVector_fn = function() {
  const key = "\v".repeat(20);
  const data = "Hi There";
  const expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
  const actual = createHmac(Core.HASH_FUNCTION_NAME, key).update(data).digest().toString("hex");
  Core.ensureTrue(actual === expected);
};
_AESTestVector = new WeakSet();
AESTestVector_fn = function() {
  const key = Buffer$1.from(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "hex"
  );
  const iv = Buffer$1.from("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex");
  const expectedPlaintext = Buffer$1.from(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "hex"
  );
  const expectedCiphertext = Buffer$1.from(
    "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
    "hex"
  );
  const computedCiphertext = Crypto.plainEncrypt(expectedPlaintext, key, iv);
  Core.ensureTrue(Buffer$1.compare(computedCiphertext, expectedCiphertext) === 0);
  const computedPlaintext = Crypto.plainDecrypt(expectedCiphertext, key, iv, Core.CIPHER_METHOD);
  Core.ensureTrue(Buffer$1.compare(computedPlaintext, expectedPlaintext) === 0);
};
__privateAdd$2(RuntimeTests, _testEncryptDecrypt);
__privateAdd$2(RuntimeTests, _HKDFTestVector);
__privateAdd$2(RuntimeTests, _HMACTestVector);
__privateAdd$2(RuntimeTests, _AESTestVector);
__privateAdd$2(RuntimeTests, _testState, 0);

var __accessCheck$1 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateAdd$1 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateMethod = (obj, member, method) => {
  __accessCheck$1(obj, member, "access private method");
  return method;
};
var _encryptInternal, encryptInternal_fn, _decryptInternal, decryptInternal_fn, _verifyHMAC, verifyHMAC_fn;
const _Crypto = class {
  static encrypt(plaintext, key, rawBinary = false) {
    var _a;
    if (typeof plaintext !== "string") {
      throw new TypeError(
        "String expected for argument 1, " + typeof plaintext + " given instead."
      );
    }
    if (!(key instanceof Key)) {
      throw new TypeError(
        "Key expected for argument 2, " + typeof key + " given instead."
      );
    }
    if (typeof rawBinary !== "boolean") {
      throw new TypeError(
        "Boolean expected for argument 3, " + typeof rawBinary + " given instead."
      );
    }
    const ciphertext = __privateMethod(_a = _Crypto, _encryptInternal, encryptInternal_fn).call(_a, plaintext, KeyOrPassword.createFromKey(key), rawBinary);
    return rawBinary ? ciphertext : ciphertext.toString("hex");
  }
  static encryptWithPassword(plaintext, password, rawBinary = false) {
    var _a;
    if (typeof plaintext !== "string") {
      throw new TypeError(
        "String expected for argument 1, " + typeof plaintext + " given instead."
      );
    }
    if (typeof password !== "string") {
      throw new TypeError(
        "String expected for argument 2, " + typeof password + " given instead."
      );
    }
    if (typeof rawBinary !== "boolean") {
      throw new TypeError(
        "Boolean expected for argument 3, " + typeof rawBinary + " given instead."
      );
    }
    const ciphertext = __privateMethod(_a = _Crypto, _encryptInternal, encryptInternal_fn).call(_a, plaintext, KeyOrPassword.createFromPassword(password), rawBinary);
    return rawBinary ? ciphertext : ciphertext.toString("hex");
  }
  static decrypt(ciphertext, key, rawBinary = false) {
    var _a;
    if (rawBinary === false && typeof ciphertext !== "string") {
      throw new TypeError(
        "String expected for argument 1, " + typeof ciphertext + " given instead."
      );
    }
    if (rawBinary === true && !(ciphertext instanceof Buffer$1)) {
      throw new TypeError(
        "Buffer expected for argument 1, " + typeof ciphertext + " given instead."
      );
    }
    if (!(key instanceof Key)) {
      throw new TypeError(
        "Key expected for argument 2, " + typeof key + " given instead."
      );
    }
    if (typeof rawBinary !== "boolean") {
      throw new TypeError(
        "Boolean expected for argument 3, " + typeof rawBinary + " given instead."
      );
    }
    return __privateMethod(_a = _Crypto, _decryptInternal, decryptInternal_fn).call(_a, ciphertext, KeyOrPassword.createFromKey(key), rawBinary).toString();
  }
  static decryptWithPassword(ciphertext, password, rawBinary = false) {
    var _a;
    if (rawBinary === false && typeof ciphertext !== "string") {
      throw new TypeError(
        "String expected for argument 1, " + typeof ciphertext + " given instead."
      );
    }
    if (rawBinary === true && !(ciphertext instanceof Buffer$1)) {
      throw new TypeError(
        "Buffer expected for argument 1, " + typeof ciphertext + " given instead."
      );
    }
    if (typeof password !== "string") {
      throw new TypeError(
        "String expected for argument 2, " + typeof password + " given instead."
      );
    }
    if (typeof rawBinary !== "boolean") {
      throw new TypeError(
        "Boolean expected for argument 3, " + typeof rawBinary + " given instead."
      );
    }
    return __privateMethod(_a = _Crypto, _decryptInternal, decryptInternal_fn).call(_a, ciphertext, KeyOrPassword.createFromPassword(password), rawBinary).toString();
  }
  static plainEncrypt(plaintext, key, iv) {
    const cipher = createCipheriv(Core.CIPHER_METHOD, key, iv);
    return Buffer$1.concat([
      cipher.update(plaintext),
      cipher.final()
    ]);
  }
  static plainDecrypt(ciphertext, key, iv, cipherMethod) {
    const decipher = createDecipheriv(cipherMethod, key, iv);
    return Buffer$1.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
  }
};
let Crypto = _Crypto;
_encryptInternal = new WeakSet();
encryptInternal_fn = function(plaintext, secret, rawBinary) {
  RuntimeTests.runtimeTest();
  const salt = randomBytes(Core.SALT_BYTE_SIZE);
  const keys = secret.deriveKeys(salt);
  const ekey = keys.getEncryptionKey();
  const akey = keys.getAuthenticationKey();
  const iv = randomBytes(Core.BLOCK_BYTE_SIZE);
  const ciphertext = Buffer$1.concat([
    Core.CURRENT_VERSION,
    salt,
    iv,
    _Crypto.plainEncrypt(plaintext, ekey, iv)
  ]);
  const auth = createHmac(Core.HASH_FUNCTION_NAME, akey).update(ciphertext).digest();
  return Buffer$1.concat([ciphertext, auth]);
};
_decryptInternal = new WeakSet();
decryptInternal_fn = function(ciphertext, secret, rawBinary) {
  var _a;
  RuntimeTests.runtimeTest();
  if (!rawBinary) {
    try {
      ciphertext = Buffer$1.from(ciphertext, "hex");
    } catch (ex) {
      if (ex instanceof BadFormatException) {
        throw new WrongKeyOrModifiedCiphertextException(
          "Ciphertext has invalid hex encoding."
        );
      }
      throw ex;
    }
  }
  if (ciphertext.length < Core.MINIMUM_CIPHERTEXT_SIZE) {
    throw new WrongKeyOrModifiedCiphertextException(
      "Ciphertext is too short."
    );
  }
  const header = Core.ourSubstr(ciphertext, 0, Core.HEADER_VERSION_SIZE);
  if (Buffer$1.compare(header, Core.CURRENT_VERSION) !== 0) {
    throw new WrongKeyOrModifiedCiphertextException(
      "Bad version header."
    );
  }
  const salt = Core.ourSubstr(
    ciphertext,
    Core.HEADER_VERSION_SIZE,
    Core.SALT_BYTE_SIZE
  );
  const iv = Core.ourSubstr(
    ciphertext,
    Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE,
    Core.BLOCK_BYTE_SIZE
  );
  const hmac = Core.ourSubstr(
    ciphertext,
    ciphertext.length - Core.MAC_BYTE_SIZE,
    Core.MAC_BYTE_SIZE
  );
  const encrypted = Core.ourSubstr(
    ciphertext,
    Core.HEADER_VERSION_SIZE + Core.SALT_BYTE_SIZE + Core.BLOCK_BYTE_SIZE,
    ciphertext.length - Core.MAC_BYTE_SIZE - Core.SALT_BYTE_SIZE - Core.BLOCK_BYTE_SIZE - Core.HEADER_VERSION_SIZE
  );
  const keys = secret.deriveKeys(salt);
  if (__privateMethod(_a = _Crypto, _verifyHMAC, verifyHMAC_fn).call(_a, hmac, Buffer$1.concat([header, salt, iv, encrypted]), keys.getAuthenticationKey())) {
    return _Crypto.plainDecrypt(encrypted, keys.getEncryptionKey(), iv, Core.CIPHER_METHOD);
  }
  throw new WrongKeyOrModifiedCiphertextException(
    "Integrity check failed."
  );
};
_verifyHMAC = new WeakSet();
verifyHMAC_fn = function(expectedHmac, message, key) {
  const messageHmac = createHmac(Core.HASH_FUNCTION_NAME, key).update(message).digest();
  return Core.hashEquals(messageHmac, expectedHmac);
};
__privateAdd$1(Crypto, _encryptInternal);
__privateAdd$1(Crypto, _decryptInternal);
__privateAdd$1(Crypto, _verifyHMAC);

var __accessCheck = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet = (obj, member, getter) => {
  __accessCheck(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet = (obj, member, value, setter) => {
  __accessCheck(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var _encryptedKey;
const _KeyProtectedByPassword = class {
  constructor(encryptedKey) {
    __privateAdd(this, _encryptedKey, "");
    __privateSet(this, _encryptedKey, encryptedKey);
  }
  static get PASSWORD_KEY_CURRENT_VERSION() {
    return Buffer$1.from([222, 241, 0, 0]);
  }
  static createRandomPasswordProtectedKey(password) {
    const innerKey = Key.createNewRandomKey();
    const encryptedKey = Crypto.encryptWithPassword(
      innerKey.saveToAsciiSafeString(),
      createHash(Core.HASH_FUNCTION_NAME).update(password).digest().toString(),
      true
    );
    return new _KeyProtectedByPassword(encryptedKey);
  }
  static loadFromAsciiSafeString(savedKeyString) {
    const encryptedKey = Encoding.loadBytesFromChecksummedAsciiSafeString(
      _KeyProtectedByPassword.PASSWORD_KEY_CURRENT_VERSION,
      savedKeyString
    );
    return new _KeyProtectedByPassword(encryptedKey);
  }
  saveToAsciiSafeString() {
    return Encoding.saveBytesToChecksummedAsciiSafeString(
      _KeyProtectedByPassword.PASSWORD_KEY_CURRENT_VERSION,
      __privateGet(this, _encryptedKey)
    );
  }
  unlockKey(password) {
    try {
      const innerKeyEncoded = Crypto.decryptWithPassword(
        __privateGet(this, _encryptedKey),
        createHash(Core.HASH_FUNCTION_NAME).update(password).digest().toString(),
        true
      );
      return Key.loadFromAsciiSafeString(innerKeyEncoded);
    } catch (ex) {
      if (ex instanceof BadFormatException) {
        throw new WrongKeyOrModifiedCiphertextException(
          "The decrypted key was found to be in an invalid format. This very likely indicates it was modified by an attacker."
        );
      }
      throw ex;
    }
  }
  changePassword(currentPassword, newPassword) {
    const innerKey = this.unlockKey(currentPassword);
    const encryptedKey = Crypto.encryptWithPassword(
      innerKey.saveToAsciiSafeString(),
      createHash(Core.HASH_FUNCTION_NAME).update(newPassword).digest().toString(),
      true
    );
    __privateSet(this, _encryptedKey, encryptedKey);
    return this;
  }
};
let KeyProtectedByPassword = _KeyProtectedByPassword;
_encryptedKey = new WeakMap();

export { Crypto, index as Exception, Key, KeyProtectedByPassword };

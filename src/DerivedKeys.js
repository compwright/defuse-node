export class DerivedKeys {
  #akey = ''

  #ekey = ''

  getAuthenticationKey () {
    return this.#akey
  }

  getEncryptionKey () {
    return this.#ekey
  }

  constructor (akey, ekey) {
    this.#akey = akey
    this.#ekey = ekey
  }
}

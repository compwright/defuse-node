# defuse-node

[![Download Status](https://img.shields.io/npm/dm/defuse-node.svg?style=flat-square)](https://www.npmjs.com/package/defuse-node)
[![Sponsor on GitHub](https://img.shields.io/static/v1?label=Sponsor&message=❤&logo=GitHub&link=https://github.com/sponsors/compwright)](https://github.com/sponsors/compwright)

Javascript port of [defuse/php-encryption](https://github.com/defuse/php-encryption) for Node.js.

> This is an unofficial port. The creators of defuse/php-encryption recommend libsodium for cross-platform use cases. Use this library at your own risk :bangbang:

This port implements everything in the official library EXCEPT for:

* File
* Crypto.legacyDecrypt()

For a compatibility demo, see https://github.com/compwright/defuse-node-compat-demo

If you would like to contribute any missing part, feel free to open a pull request.

## Requirements

Node.js 24+ with OpenSSL

## Installation

With NPM:

```
$ npm install --save defuse-node
```

With Yarn:

```
$ yarn add defuse-node
```

## Quick Start

```javascript
import { Key, Crypto } from 'defuse-node'

const key = Key.loadFromAsciiSafeString('...')

// Encrypt
const data = 'Hello, world'
const ciphertext = Crypto.encrypt(data, key)

// Decrypt
const plaintext = Crypto.decrypt(ciphertext, key)
```

## Documentation

See https://github.com/defuse/php-encryption#getting-started

## License

MIT License

import { describe, expect, test } from '@jest/globals'
import { Buffer } from 'buffer'
import { Core } from '../src/Core'

describe('Core', () => {
  describe('ourSubstr()', () => {
    const buf = Buffer.from('abc')

    test('negative length', () => {
      expect(() => Core.ourSubstr(buf, 0, -1).toString())
        .toThrow(Error)
    })

    test('negative start', () => {
      expect(Core.ourSubstr(buf, -1, 1).toString()).toBe('c')
    })

    test('length is max', () => {
      expect(Core.ourSubstr(buf, 1, 500).toString()).toBe('bc')
    })
  })
})

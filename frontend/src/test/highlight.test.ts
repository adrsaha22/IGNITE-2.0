/**
 * Tokenizer tests.
 *
 * Highlighting is presentational: it must never drop, reorder or alter the
 * source text, and an unrecognised construct must pass through as plain text.
 */

import { describe, expect, it } from 'vitest'
import { tokenizeJSON, tokenizeSPL } from '@/lib/highlight'

const SPL = 'index=sysmon EventCode=1 Image="*powershell.exe*" | stats count by host'

describe('tokenizeSPL', () => {
  it('reproduces the source exactly', () => {
    // The critical property: colouring must not corrupt the query.
    expect(tokenizeSPL(SPL).map((t) => t.text).join('')).toBe(SPL)
  })

  it('marks field names before an equals sign', () => {
    const tokens = tokenizeSPL('Image="x"')
    expect(tokens[0]).toEqual({ text: 'Image', kind: 'field' })
  })

  it('marks quoted strings', () => {
    const tokens = tokenizeSPL('Image="*powershell.exe*"')
    expect(tokens.some((t) => t.kind === 'string' && t.text.includes('powershell'))).toBe(true)
  })

  it('marks boolean operators only when uppercase', () => {
    expect(tokenizeSPL('a OR b').some((t) => t.kind === 'operator' && t.text === 'OR')).toBe(true)
    // "or" as part of ordinary text is not an operator.
    expect(tokenizeSPL('sensor').every((t) => t.kind !== 'operator')).toBe(true)
  })

  it('marks pipeline commands', () => {
    expect(tokenizeSPL('| stats count').some((t) => t.kind === 'command')).toBe(true)
  })

  it('handles an empty string', () => {
    expect(tokenizeSPL('')).toEqual([])
  })

  it('passes unknown constructs through as plain text', () => {
    const weird = '@@ ~~ %%'
    expect(tokenizeSPL(weird).map((t) => t.text).join('')).toBe(weird)
  })

  it('preserves newlines and indentation', () => {
    const multi = 'index=a\n  | stats count\n'
    expect(tokenizeSPL(multi).map((t) => t.text).join('')).toBe(multi)
  })
})

describe('tokenizeJSON', () => {
  const json = '{\n  "score": 105,\n  "valid": true,\n  "name": "PowerShell"\n}'

  it('reproduces the source exactly', () => {
    expect(tokenizeJSON(json).map((t) => t.text).join('')).toBe(json)
  })

  it('distinguishes keys from string values', () => {
    const tokens = tokenizeJSON('{"name": "PowerShell"}')
    expect(tokens.some((t) => t.kind === 'key' && t.text === '"name"')).toBe(true)
    expect(tokens.some((t) => t.kind === 'string' && t.text === '"PowerShell"')).toBe(true)
  })

  it('marks numbers and booleans', () => {
    const tokens = tokenizeJSON('{"a": 105, "b": true}')
    expect(tokens.some((t) => t.kind === 'number' && t.text === '105')).toBe(true)
    expect(tokens.some((t) => t.kind === 'boolean' && t.text === 'true')).toBe(true)
  })
})

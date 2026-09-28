import { describe, expect, it } from 'vitest'
import { isScoreOutOfRange, scorePercent, scoreTone } from '@/lib/utils'

describe('scorePercent', () => {
  it('scales a value against its own maximum', () => {
    expect(scorePercent(105, 125)).toBeCloseTo(84)
    expect(scorePercent(50, 100)).toBe(50)
  })

  it('clamps a value above the maximum to 100 so a bar cannot overflow', () => {
    expect(scorePercent(150, 100)).toBe(100)
  })

  it('clamps negatives to zero', () => {
    expect(scorePercent(-10, 100)).toBe(0)
  })

  it('returns zero for missing or non-finite values', () => {
    expect(scorePercent(null, 100)).toBe(0)
    expect(scorePercent(undefined, 100)).toBe(0)
    expect(scorePercent(Number.NaN, 100)).toBe(0)
  })

  it('returns zero when the maximum is invalid', () => {
    expect(scorePercent(50, 0)).toBe(0)
  })
})

describe('isScoreOutOfRange', () => {
  it('flags a score above its declared scale', () => {
    // The key case: 105 on a /100 scale must be reported, not drawn silently.
    expect(isScoreOutOfRange(105, 100)).toBe(true)
  })

  it('accepts a score within its own larger scale', () => {
    expect(isScoreOutOfRange(105, 125)).toBe(false)
  })

  it('flags negatives', () => {
    expect(isScoreOutOfRange(-1, 100)).toBe(true)
  })

  it('ignores missing values', () => {
    expect(isScoreOutOfRange(null, 100)).toBe(false)
  })
})

describe('scoreTone', () => {
  it('grades against the declared maximum, not a fixed 100', () => {
    expect(scoreTone(100, 125)).toBe('ok')
    expect(scoreTone(70, 125)).toBe('warn')
    expect(scoreTone(20, 125)).toBe('bad')
  })

  it('returns neutral for missing values', () => {
    expect(scoreTone(null, 100)).toBe('neutral')
  })
})

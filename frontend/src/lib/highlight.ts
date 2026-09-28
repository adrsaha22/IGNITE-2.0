/**
 * Minimal SPL and JSON tokenizers for the code panel.
 *
 * These colour text only — they never parse, validate or rewrite a query, and
 * an unrecognised token is emitted verbatim as plain text. Highlighting a rule
 * says nothing about whether it is syntactically valid SPL.
 */

export type TokenKind =
  | 'plain'
  | 'command'
  | 'field'
  | 'string'
  | 'number'
  | 'operator'
  | 'comment'
  | 'key'
  | 'punctuation'
  | 'boolean'

export interface Token {
  text: string
  kind: TokenKind
}

/** Leading search commands and pipeline verbs used by the generated rules. */
const SPL_COMMANDS = new Set([
  'search',
  'stats',
  'count',
  'by',
  'where',
  'eval',
  'table',
  'sort',
  'dedup',
  'rename',
  'fields',
  'index',
  'sourcetype',
  'tstats',
  'values',
  'head',
  'top',
])

const SPL_OPERATORS = new Set(['AND', 'OR', 'NOT'])

/**
 * Tokenize a Splunk SPL query for display.
 *
 * Deliberately conservative: quoted strings, comments, pipes, field=value
 * pairs, numbers and boolean operators. Everything else stays plain.
 */
export function tokenizeSPL(source: string): Token[] {
  const tokens: Token[] = []
  // Order matters: comments and strings first so their contents are not
  // re-tokenized as operators or fields.
  const pattern =
    /(#[^\n]*)|("(?:[^"\\]|\\.)*")|(\|)|([A-Za-z_][\w.]*)(\s*=)|\b(\d+(?:\.\d+)?)\b|([A-Za-z_][\w.]*)|(\s+)|([^\s])/g

  let match: RegExpExecArray | null
  while ((match = pattern.exec(source)) !== null) {
    const [, comment, str, pipe, fieldName, equals, num, word, space, other] = match

    if (comment) {
      tokens.push({ text: comment, kind: 'comment' })
    } else if (str) {
      tokens.push({ text: str, kind: 'string' })
    } else if (pipe) {
      tokens.push({ text: pipe, kind: 'punctuation' })
    } else if (fieldName && equals) {
      tokens.push({ text: fieldName, kind: 'field' })
      tokens.push({ text: equals, kind: 'operator' })
    } else if (num) {
      tokens.push({ text: num, kind: 'number' })
    } else if (word) {
      if (SPL_OPERATORS.has(word.toUpperCase()) && word === word.toUpperCase()) {
        tokens.push({ text: word, kind: 'operator' })
      } else if (SPL_COMMANDS.has(word.toLowerCase())) {
        tokens.push({ text: word, kind: 'command' })
      } else {
        tokens.push({ text: word, kind: 'plain' })
      }
    } else if (space) {
      tokens.push({ text: space, kind: 'plain' })
    } else if (other) {
      tokens.push({ text: other, kind: 'punctuation' })
    }
  }

  return tokens
}

/** Tokenize JSON for the export preview. */
export function tokenizeJSON(source: string): Token[] {
  const tokens: Token[] = []
  const pattern =
    /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|\b(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|(\s+)|([^\s])/g

  let match: RegExpExecArray | null
  while ((match = pattern.exec(source)) !== null) {
    const [, str, colon, bool, num, space, other] = match

    if (str) {
      // A string immediately followed by a colon is an object key.
      tokens.push({ text: str, kind: colon ? 'key' : 'string' })
      if (colon) tokens.push({ text: colon, kind: 'punctuation' })
    } else if (bool) {
      tokens.push({ text: bool, kind: 'boolean' })
    } else if (num) {
      tokens.push({ text: num, kind: 'number' })
    } else if (space) {
      tokens.push({ text: space, kind: 'plain' })
    } else if (other) {
      tokens.push({ text: other, kind: 'punctuation' })
    }
  }

  return tokens
}

/** Token colour classes, resolved from theme tokens so both themes work. */
export const TOKEN_CLASS: Record<TokenKind, string> = {
  plain: 'text-ink',
  command: 'text-primary-bright font-medium',
  field: 'text-accent',
  string: 'text-ok',
  number: 'text-primary-lavender',
  operator: 'text-ink-muted',
  comment: 'text-ink-faint italic',
  key: 'text-accent',
  punctuation: 'text-ink-muted',
  boolean: 'text-primary-lavender',
}

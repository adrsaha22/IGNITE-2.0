/**
 * Types mirroring the FastAPI contract in api/schemas/analysis.py.
 * Kept in sync by hand; the backend is the source of truth.
 */

export interface Technique {
  id: string
  name: string
  /** Always null: the current Python pipeline does not map tactics. */
  tactic: string | null
}

export interface CandidateRule {
  spl: string
  score: number
  /** Candidate scores use their own scale; rule_scorer can exceed 100. */
  score_max: number
  origin: string
  /** Static text check only — not SPL syntax validation. */
  has_conditions: boolean
}

export interface Entities {
  tools: string[]
  indicators: string[]
  logs: string[]
  fields: string[]
}

export interface Telemetry {
  logs: string[]
  fields: string[]
  events: number[]
  indicators: string[]
}

export interface Validation {
  valid: boolean | null
  score: number | null
  score_max: number
  issues: string[]
}

export interface Quality {
  quality_score: number | null
  score_max: number
  strengths: string[]
  weaknesses: string[]
}

export interface AutonomousEngine {
  available: boolean
  error: string | null
  techniques: Technique[]
  telemetry: Telemetry
  telemetry_rule: string
  rule: string
  rule_has_conditions: boolean
  validation: Validation
  quality: Quality
  explanation: string
}

export interface SigmaReference {
  title: string
  spl: string
  tags: string[]
  logsource: Record<string, unknown>
  score: number | null
  status: string | null
}

export interface Analysis {
  description: string
  generated_at: string
  primary_technique: Technique
  entities: Entities
  candidates: CandidateRule[]
  best: CandidateRule | null
  autonomous: AutonomousEngine
  sigma_references: SigmaReference[]
  warnings: string[]
  rule_status: string
}

export interface AIStatus {
  available: boolean
  detail: string
  checked_at: string
}

export interface AIResult {
  available: boolean
  text: string | null
  error: string | null
}

export interface Health {
  status: string
  mitre_techniques_loaded: number
  sigma_corpus_available: boolean
  ai: AIStatus
}

/* ------------------------------------------------------ AI Copilot */

export interface CopilotSection {
  heading: string
  body: string
}

export interface CopilotResult {
  ok: boolean
  /** Distinct failure reasons so the UI can be specific. */
  status:
    | 'ok'
    | 'not_configured'
    | 'unauthorized'
    | 'rate_limited'
    | 'timeout'
    | 'unreachable'
    | 'provider_error'
    | 'malformed'
    | 'blocked'
  /** Plain text. Rendered as text, never as HTML. */
  text: string
  sections: CopilotSection[]
  message: string
  model: string
  ai_generated: boolean
}

export interface CopilotStatus {
  configured: boolean
  model: string
  provider: string
  message: string
}

export interface CopilotContext {
  scenario?: string
  rule?: string
  rule_origin?: string
  techniques?: { id: string; name: string }[]
  validation_issues?: string[]
  quality?: Record<string, unknown>
  entities?: Record<string, unknown>
}

export type CopilotAction =
  | 'explain_rule'
  | 'explain_conditions'
  | 'find_gaps'
  | 'reduce_false_positives'
  | 'explain_validation'
  | 'explain_attack'
  | 'suggest_telemetry'
  | 'ask'

export interface CopilotTurn {
  role: 'user' | 'assistant'
  content: string
}

/* ----------------------------------------------------- Testing Lab */

export interface FieldObservation {
  field: string
  operator: string
  expected: string
  actual: string | null
  matched: boolean
  missing: boolean
}

export interface EventResult {
  event_id: string
  outcome: 'match' | 'no_match' | 'undetermined'
  observations: FieldObservation[]
  missing_fields: string[]
  reason: string
}

export interface RuleTestResult {
  supported: boolean
  results: EventResult[]
  /** Constructs the local evaluator deliberately did not apply. */
  unsupported: string[]
  referenced_fields: string[]
  error: string
  matched_count: number
  total_count: number
  /** Always "local_sample" — never external Splunk validation. */
  validation_mode: string
  disclaimer: string
}

export interface SampleSet {
  key: string
  label: string
  description: string
  events: Record<string, unknown>[]
}

/* -------------------------------------------------- Investigations */

export interface InvestigationSummary {
  id: string
  title: string
  notes: string
  created_at: string
  updated_at: string
  schema_version: number
}

export interface InvestigationDetail extends InvestigationSummary {
  payload: Record<string, unknown>
  /** Set when the record was saved under a different schema version. */
  warning: string
}

/* ------------------------------------------ LLM rule generation */

export interface AttackMapping {
  id: string
  /** Canonical name from the ATT&CK dataset, never from the model. */
  name: string
  /** The ID exists in the bundled dataset and is not revoked. */
  reference_verified: boolean
  /** Evidence was also supplied linking this detection to the technique. */
  mapping_supported: boolean
  status: 'supported' | 'needs_review' | 'unknown_id' | 'revoked' | 'malformed_id'
  evidence: string
  note: string
  is_subtechnique: boolean
  tactics: string[]
}

/** Which validation stages actually ran. Never conflated. */
export interface ValidationProvenance {
  static_checks: string
  local_sample_test: string
  splunk_syntax_validation: string
  real_telemetry_validation: string
}

export interface CandidateProvenance {
  /** "llm" for Gemini output, "template" for offline demo output. */
  generator: string
  provider: string
  model: string
  prompt_version: string
  generated_at: string
  attack_dataset_version: string
  validation: ValidationProvenance
  /** Present and true only for offline demo candidates. */
  demo_mode?: boolean
  template_version?: string
  template_key?: string
}

export interface GeneratedCandidate {
  name: string
  purpose: string
  spl: string
  hypothesis: string
  behaviors: string[]
  attack_mappings: AttackMapping[]
  log_source: {
    index?: string
    sourcetype?: string
    fields?: string[]
    event_ids?: number[]
  }
  assumptions: string[]
  expected_positive_characteristics: string[]
  benign_near_matches: string[]
  blind_spots: string[]
  required_telemetry: string[]
  references: string[]
  /** Findings from the backend's deterministic checks, not the model's. */
  static_findings: string[]
  provenance: CandidateProvenance
}

export interface GenerateRulesResult {
  ok: boolean
  candidates: GeneratedCandidate[]
  status: string
  message: string
  provenance: Record<string, unknown>
  generator: string
  /** "gemini" or "demo". Demo candidates are template-based. */
  mode?: string
}

export interface AttackDatasetInfo {
  source: string
  version: string
  loaded_at: string
  current_techniques: number
  revoked_excluded: number
  available: boolean
}

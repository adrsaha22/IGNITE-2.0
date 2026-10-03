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

/* ------------------------------------------------------ AI Detection Assistant */

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
  /** "run" once the weighted quality checks have run. */
  quality_checks?: string
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
  /** Reference detections the model was given. */
  grounding?: { knowledge_base: string; references: GroundingReference[] }
  repair_attempts?: number
  repair_note?: string
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
  /** Optional: absent on records saved before quality checks existed. */
  sigma_rule?: string
  spl_from_sigma?: string
  severity?: string
  response_actions?: string[]
  how_to_implement?: string
  validation?: QualityValidation
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

/* ------------------------------------------------- Quality checks */

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'skip'

export interface QualityCheck {
  name: string
  status: CheckStatus
  detail: string
  weight: number
}

/** Weighted quality checks computed by the backend (validators.summarize). */
export interface QualityValidation {
  checks: QualityCheck[]
  passed: boolean
  quality_score: number
  quality_grade: 'Ready' | 'Good' | 'Needs work' | 'Poor' | string
  failures: string[]
  splunk_parser: 'not_configured' | 'passed' | 'failed' | string
  validated_at?: string
}

export interface GroundingReference {
  id: string
  title: string
  source: string
  technique_ids: string[]
  score: number | null
}

/* --------------------------------------------------- Rule library */

export type RuleStatus = 'draft' | 'approved' | 'rejected'
export type DeployMode = 'disabled' | 'shadow' | 'live'

export interface RuleSummary {
  id: string
  title: string
  status: RuleStatus
  severity: string
  quality_score: number
  quality_grade: string
  passed: boolean
  technique_ids: string[]
  deployment_mode: DeployMode | ''
  deployment_stale: boolean
  version: number
  created_at: string
  updated_at: string
  created_by: string
  demo: boolean
}

export interface RuleReview {
  decision: 'approve' | 'reject'
  by: string
  at: string
  note: string
  override: boolean
  override_justification: string
  quality_score: number | null
  version: number
}

export interface RuleDeployment {
  name: string
  action: string
  mode: DeployMode
  app: string
  at: string
  by: string
  cron: string
  earliest: string
  version: number
  stale: boolean
}

export interface LibraryRule {
  id: string
  title: string
  description: string
  scenario: string
  spl: string
  sigma_rule: string
  spl_from_sigma: string
  severity: string
  attack_mappings: AttackMapping[]
  benign_near_matches: string[]
  response_actions: string[]
  how_to_implement: string
  hypothesis?: string
  assumptions?: string[]
  blind_spots?: string[]
  log_source?: GeneratedCandidate['log_source']
  validation: QualityValidation
  provenance: Partial<CandidateProvenance> & Record<string, unknown>
  status: RuleStatus
  review: RuleReview | null
  deployment: RuleDeployment | null
  version: number
  created_at: string
  updated_at: string
  created_by: string
  versions: { version: number; saved_at: string; actor: string }[]
}

export interface RuleUpdate {
  expected_version: number
  note?: string
  title?: string
  description?: string
  spl?: string
  sigma_rule?: string
  severity?: string
  benign_near_matches?: string[]
  response_actions?: string[]
  how_to_implement?: string
  attack_mappings?: { id: string; evidence: string }[]
}

export type ExportFormat = 'contentctl' | 'savedsearches' | 'sigma' | 'markdown' | 'json'

export interface AuditEntry {
  seq: number
  at: string
  actor: string
  action: string
  rule_id: string
  rule_title: string
  detail: string
}

/* ------------------------------------------------------- Coverage */

export type CoverageLevel = 'deployed' | 'approved' | 'draft' | 'reference' | null

export interface CoverageTechnique {
  id: string
  name: string
  level: CoverageLevel
  rules: { id: string; title: string; level: CoverageLevel }[]
  rule_count: number
  references: number
}

export interface CoverageTactic {
  key: string
  title: string
  techniques: CoverageTechnique[]
  total: number
  covered: number
  coverage_pct: number
}

export interface Coverage {
  tactics: CoverageTactic[]
  summary: {
    techniques: number
    by_level: Record<'deployed' | 'approved' | 'draft' | 'reference', number>
    covered: number
    coverage_pct: number
  }
  attack_version: string
}

/* ------------------------------------------------------- Platform */

export interface SplunkStatus {
  configured: boolean
  url: string
  app: string
  verify_ssl: boolean
  auth: 'token' | 'basic' | 'none'
  reachable: boolean | null
  server: string
  version: string
  message: string
  deploy_modes: Record<DeployMode, string>
}

export interface ProviderStatus {
  provider: string
  label: string
  model: string
  configured: boolean
  available_providers: string[]
  message: string
  data_leaves_network: boolean
  generation_mode: string
}

export interface KnowledgeStatus {
  location: 'built' | 'bundled_sample' | string
  path: string
  counts: Record<string, number>
  techniques_covered: number | null
  sources: Record<string, unknown>
  approved_rules: number
  retrieval: string
  last_evaluation: Record<string, number | string> | null
}

export interface PlatformStatus {
  provider: ProviderStatus
  splunk: SplunkStatus
  knowledge: KnowledgeStatus
  library: Record<'draft' | 'approved' | 'rejected' | 'deployed', number>
  operator: string
  pysigma: boolean
}

/* ---------------------------------------------------- AI switcher */

export type AIChoice = 'gemini' | 'anthropic' | 'openai' | 'ollama' | 'ellm' | 'demo'

export interface AIProviderOption {
  id: AIChoice
  label: string
  model: string
  /** The key is present in the backend .env (always true for Ollama and Demo). */
  configured: boolean
  /** Configured, and for Ollama the server is up with the model installed. */
  ready: boolean
  message: string
  local: boolean
  key_env: string
}

export interface AIProviders {
  active: AIChoice
  env_default: AIChoice
  /** True when the dashboard choice differs from the .env default. */
  overridden: boolean
  options: AIProviderOption[]
}

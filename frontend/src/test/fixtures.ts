/**
 * TEST FIXTURES ONLY.
 *
 * Hand-written stand-ins for API responses, used exclusively by unit tests.
 * These are never imported by application code and are never displayed as if
 * they were live results.
 */

import type { Analysis } from '@/types/api'

export const FIXTURE_ANALYSIS: Analysis = {
  description: 'Attacker used PowerShell DownloadString and schtasks persistence',
  generated_at: '2026-01-15T10:30:00+00:00',
  primary_technique: { id: 'T1059.001', name: 'PowerShell', tactic: null },
  entities: {
    tools: ['powershell.exe'],
    indicators: ['DownloadString', 'IEX'],
    logs: ['Sysmon'],
    fields: ['Image', 'CommandLine'],
  },
  candidates: [
    {
      spl: 'index=sysmon EventCode=1 Image="*powershell.exe*" | stats count',
      score: 105,
      score_max: 125,
      origin: 'Entity-derived rule',
      has_conditions: true,
    },
    {
      spl: 'index=sysmon EventCode=1 ()\n| stats count',
      score: 40,
      score_max: 125,
      origin: 'MITRE context rule',
      has_conditions: false,
    },
  ],
  best: {
    spl: 'index=sysmon EventCode=1 Image="*powershell.exe*" | stats count',
    score: 105,
    score_max: 125,
    origin: 'Entity-derived rule',
    has_conditions: true,
  },
  autonomous: {
    available: true,
    error: null,
    techniques: [
      { id: 'T1059.001', name: 'PowerShell', tactic: null },
      { id: 'T1105', name: 'Ingress Tool Transfer', tactic: null },
    ],
    telemetry: {
      logs: ['Sysmon'],
      fields: ['Image', 'CommandLine'],
      events: [1, 4104],
      indicators: ['powershell.exe'],
    },
    telemetry_rule: 'index=sysmon (EventCode=1) | stats count',
    rule: 'index=sysmon EventCode=1 Image="*powershell.exe*" | stats count',
    rule_has_conditions: true,
    validation: { valid: true, score: 100, score_max: 100, issues: [] },
    quality: {
      quality_score: 70,
      score_max: 100,
      strengths: ['Uses process creation events'],
      weaknesses: ['Broad OR logic may create false positives'],
    },
    explanation: 'Monitors PowerShell execution activity.',
  },
  sigma_references: [],
  warnings: ['No Sigma rules were matched — the data/sigma directory appears to be empty.'],
  rule_status: 'generated — not validated against a live Splunk instance',
}

/** A report where the validator passes the rule yet still lists an issue. */
export const FIXTURE_CONTRADICTORY: Analysis = {
  ...FIXTURE_ANALYSIS,
  autonomous: {
    ...FIXTURE_ANALYSIS.autonomous,
    validation: {
      valid: true,
      score: 80,
      score_max: 100,
      issues: ['No attack indicators found'],
    },
  },
}

/** An analysis where the autonomous engine failed. */
export const FIXTURE_ENGINE_DOWN: Analysis = {
  ...FIXTURE_ANALYSIS,
  autonomous: {
    ...FIXTURE_ANALYSIS.autonomous,
    available: false,
    error: 'RuntimeError: engine exploded',
  },
}

/** An analysis with no entities, techniques or candidates. */
export const FIXTURE_EMPTY: Analysis = {
  ...FIXTURE_ANALYSIS,
  primary_technique: { id: 'Unknown', name: '', tactic: null },
  entities: { tools: [], indicators: [], logs: [], fields: [] },
  candidates: [],
  best: null,
  autonomous: {
    ...FIXTURE_ANALYSIS.autonomous,
    techniques: [],
    telemetry: { logs: [], fields: [], events: [], indicators: [] },
    explanation: '',
  },
  warnings: [],
}


/* ---------------------------------------------- Generation fixtures */

/**
 * TEST FIXTURE ONLY — a stand-in for a /api/rules/generate response.
 * Never imported by application code.
 */
export const FIXTURE_GENERATION = {
  ok: true,
  status: 'ok',
  message: '',
  generator: 'llm',
  provenance: {},
  candidates: [
    {
      name: 'PowerShell download cradle',
      purpose: 'Detects in-memory payload download via PowerShell.',
      spl: 'index=sysmon EventCode=1 Image="*powershell.exe*" CommandLine="*DownloadString*"',
      hypothesis: 'Attackers use DownloadString to stage payloads.',
      behaviors: ['process creation'],
      attack_mappings: [
        {
          id: 'T1059.001',
          name: 'PowerShell',
          reference_verified: true,
          mapping_supported: true,
          status: 'supported',
          evidence: 'Scenario shows powershell.exe execution',
          note: '',
          is_subtechnique: true,
          tactics: ['execution'],
        },
      ],
      log_source: {
        index: 'sysmon',
        sourcetype: 'XmlWinEventLog',
        fields: ['Image', 'CommandLine'],
        event_ids: [1],
      },
      assumptions: ['Sysmon EventCode 1 is collected'],
      expected_positive_characteristics: ['CommandLine contains DownloadString'],
      benign_near_matches: ['Admin scripts using Invoke-WebRequest'],
      blind_spots: ['Obfuscated command lines'],
      required_telemetry: ['Sysmon process creation'],
      references: ['MITRE ATT&CK T1059.001'],
      static_findings: [],
      provenance: {
        generator: 'llm',
        provider: 'google-gemini',
        model: 'gemini-flash-latest',
        prompt_version: 'rulegen/2',
        generated_at: '2026-01-15T10:30:00+00:00',
        attack_dataset_version: '2026-08-04T20:30:56.386Z',
        validation: {
          static_checks: 'run',
          local_sample_test: 'not_run',
          splunk_syntax_validation: 'not_configured',
          real_telemetry_validation: 'not_run',
        },
      },
    },
    {
      name: 'Broad PowerShell catch-all',
      purpose: 'Second candidate, deliberately over-broad.',
      spl: 'index=sysmon Image="*"',
      hypothesis: 'Catches any process.',
      behaviors: [],
      attack_mappings: [
        {
          id: 'T9999.999',
          name: '',
          reference_verified: false,
          mapping_supported: false,
          status: 'unknown_id',
          evidence: 'invented',
          note: 'T9999.999 is not a current technique.',
          is_subtechnique: false,
          tactics: [],
        },
      ],
      log_source: { index: 'sysmon', fields: [] },
      assumptions: [],
      expected_positive_characteristics: [],
      benign_near_matches: [],
      blind_spots: [],
      required_telemetry: [],
      references: [],
      static_findings: ['`Image="*"` matches every value and does not filter anything.'],
      provenance: {
        generator: 'llm',
        provider: 'google-gemini',
        model: 'gemini-flash-latest',
        prompt_version: 'rulegen/2',
        generated_at: '2026-01-15T10:30:00+00:00',
        attack_dataset_version: '2026-08-04T20:30:56.386Z',
        validation: {
          static_checks: 'run',
          local_sample_test: 'not_run',
          splunk_syntax_validation: 'not_configured',
          real_telemetry_validation: 'not_run',
        },
      },
    },
  ],
}

/** A failure response, e.g. no API key configured. */
export const FIXTURE_GENERATION_FAILED = {
  ok: false,
  status: 'not_configured',
  message: 'The AI Copilot is not configured.',
  generator: 'llm',
  provenance: {},
  candidates: [],
}


/** TEST FIXTURE ONLY — an offline demo (template) generation response. */
export const FIXTURE_DEMO_GENERATION = {
  ok: true,
  status: 'ok',
  message: '',
  generator: 'template',
  mode: 'demo',
  provenance: {},
  candidates: [
    {
      name: '[DEMO] Certutil LOLBin transfer',
      purpose: 'Detects certutil.exe retrieving or decoding a remote file.',
      spl: 'index=sysmon EventCode=1 Image="*\\\\certutil.exe" CommandLine="*-urlcache*"',
      hypothesis: 'certutil is abused to download payloads.',
      behaviors: ['process creation'],
      attack_mappings: [
        {
          id: 'T1105',
          name: 'Ingress Tool Transfer',
          reference_verified: true,
          mapping_supported: true,
          status: 'supported',
          evidence: "Scenario mentions 'certutil'.",
          note: '',
          is_subtechnique: false,
          tactics: ['command-and-control'],
        },
      ],
      log_source: { index: 'sysmon', fields: ['Image', 'CommandLine'], event_ids: [1] },
      assumptions: [
        'This is a pre-written template, not a rule generated for this specific scenario.',
      ],
      expected_positive_characteristics: ['certutil with -urlcache'],
      benign_near_matches: ['PKI admin fetching a CRL'],
      blind_spots: ['Renamed certutil.exe'],
      required_telemetry: ['Sysmon EventCode 1'],
      references: ['MITRE ATT&CK T1105'],
      static_findings: [],
      provenance: {
        generator: 'template',
        provider: 'none',
        model: '',
        prompt_version: '',
        template_version: 'demo/1',
        template_key: 'certutil_transfer',
        generated_at: '2026-01-15T10:30:00+00:00',
        attack_dataset_version: '2026-08-04T20:30:56.386Z',
        demo_mode: true,
        validation: {
          static_checks: 'run',
          local_sample_test: 'not_run',
          splunk_syntax_validation: 'not_configured',
          real_telemetry_validation: 'not_run',
        },
      },
    },
  ],
}

/** A demo-mode refusal for an unsupported scenario. */
export const FIXTURE_DEMO_UNSUPPORTED = {
  ok: false,
  status: 'unsupported_in_demo_mode',
  message:
    'Demo mode has no template covering this scenario. It supports only PowerShell download cradles, certutil transfers, and scheduled-task persistence.',
  generator: 'template',
  mode: 'demo',
  provenance: {},
  candidates: [],
}

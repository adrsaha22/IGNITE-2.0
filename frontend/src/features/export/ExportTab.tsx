import { Braces, Copy, Download, FileCode, Layers } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import type { Analysis } from '@/types/api'
import { copyText, downloadText, fileStamp, formatTimestamp } from '@/lib/utils'

/** Builds the export document from the analysis currently in state, so an
 *  export can never contain results from an earlier run. */
function buildExport(analysis: Analysis, selectedIndex: number) {
  const selected = analysis.candidates[selectedIndex] ?? analysis.best
  return {
    metadata: {
      tool: 'IGNITE 2.0 — AI Detection Rule Generator',
      generated_at: analysis.generated_at,
      attack_description: analysis.description,
      query_language: 'Splunk SPL',
      rule_status: analysis.rule_status,
      selected_rule_index: selectedIndex,
    },
    mitre: {
      primary_technique: analysis.primary_technique,
      mapped_techniques: analysis.autonomous.techniques,
    },
    entities: analysis.entities,
    selected_rule: selected,
    best_rule: analysis.best,
    candidate_rules: analysis.candidates,
    autonomous_engine: {
      available: analysis.autonomous.available,
      error: analysis.autonomous.error,
      rule: analysis.autonomous.rule,
      telemetry_rule: analysis.autonomous.telemetry_rule,
      telemetry: analysis.autonomous.telemetry,
      validation: analysis.autonomous.validation,
      quality: analysis.autonomous.quality,
      explanation: analysis.autonomous.explanation,
    },
    sigma_references: analysis.sigma_references,
    warnings: analysis.warnings,
  }
}

export function ExportTab({
  analysis,
  selectedIndex,
}: {
  analysis: Analysis
  selectedIndex: number
}) {
  const toast = useToast()
  const stamp = fileStamp(analysis.generated_at)
  const selected = analysis.candidates[selectedIndex] ?? analysis.best
  const payload = buildExport(analysis, selectedIndex)
  const json = JSON.stringify(payload, null, 2)

  async function handleCopy() {
    const ok = await copyText((selected?.spl ?? '').trim())
    toast(ok ? 'Selected rule copied' : 'Could not copy to clipboard', ok ? 'success' : 'error')
  }

  function handleDownload(filename: string, content: string, mime?: string) {
    downloadText(filename, content, mime)
    toast(`Downloading ${filename}`, 'success')
  }

  return (
    <div className="space-y-5">
      <Panel>
        <PanelHeader
          title="Export analysis"
          description={`Reflects the analysis generated ${formatTimestamp(
            analysis.generated_at,
          )} for the description shown in Overview.`}
          icon={<Download className="size-4" />}
          actions={
            selected ? (
              <Badge tone="primary">
                Rule #{selectedIndex + 1} selected · {selected.origin}
              </Badge>
            ) : undefined
          }
        />

        <div className="grid gap-3 p-4 sm:grid-cols-2">
          <Button
            variant="primary"
            onClick={() =>
              handleDownload(`ignite_analysis_${stamp}.json`, json, 'application/json')
            }
          >
            <Braces />
            Full analysis (JSON)
          </Button>

          <Button
            variant="outline"
            disabled={!selected?.spl.trim()}
            onClick={() =>
              handleDownload(
                `ignite_rule_${selectedIndex + 1}_${stamp}.spl`,
                `${(selected?.spl ?? '').trim()}\n`,
              )
            }
          >
            <FileCode />
            Selected rule (.spl)
          </Button>

          <Button
            variant="outline"
            disabled={analysis.candidates.length < 2}
            onClick={() =>
              handleDownload(
                `ignite_all_rules_${stamp}.spl`,
                analysis.candidates
                  .map(
                    (rule, index) =>
                      `# Candidate ${index + 1} — ${rule.origin} — score ${rule.score}/${
                        rule.score_max
                      }\n${rule.spl.trim()}`,
                  )
                  .join('\n\n') + '\n',
              )
            }
          >
            <Layers />
            All candidates (.spl)
          </Button>

          <Button variant="outline" disabled={!selected?.spl.trim()} onClick={handleCopy}>
            <Copy />
            Copy selected rule
          </Button>
        </div>
      </Panel>

      <Panel>
        <PanelHeader title="Export preview" icon={<Braces className="size-4" />} />
        <div className="p-4">
          <SectionLabel>JSON payload</SectionLabel>
          <pre
            className="overflow-auto rounded-md border border-line bg-canvas px-3.5 py-3 font-mono text-[0.75rem] leading-relaxed text-ink-muted"
            style={{ maxHeight: 420 }}
          >
            {json}
          </pre>
        </div>
      </Panel>
    </div>
  )
}

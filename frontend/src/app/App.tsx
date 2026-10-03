import { Suspense, lazy, useCallback, useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  Braces,
  Crosshair,
  FlaskConical,
  FolderOpen,
  LayoutDashboard,
  ShieldCheck,
  Target,
  TriangleAlert,
} from 'lucide-react'
import { Shell, type View } from './Shell'

import { AIPanel } from '@/features/analysis/AIPanel'
import { AttackInput } from '@/features/analysis/AttackInput'
import { OverviewTab } from '@/features/analysis/OverviewTab'
import { IntelTab } from '@/features/attack-intelligence/IntelTab'
import { RulesTab } from '@/features/detection-rules/RulesTab'
import { ExportTab } from '@/features/export/ExportTab'
import { ValidationTab } from '@/features/validation/ValidationTab'
import { CopilotPanel } from '@/features/copilot/CopilotPanel'
import { TestLabTab, type TestCase } from '@/features/testlab/TestLabTab'
import { LibraryPanel } from '@/features/library/LibraryPanel'
import { useInvestigations } from '@/hooks/useInvestigations'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/primitives'
import { isStale, useAnalysis } from '@/hooks/useAnalysis'
import { useAIStatus } from '@/hooks/useAIStatus'
import { useAIProviders } from '@/hooks/useAIProviders'
import { AISwitcher } from '@/components/ui/ai-switcher'
import { useHistory, type HistoryEntry } from '@/hooks/useHistory'
import { useReducedMotion } from '@/lib/motion'
import { getHealth, getPlatformStatus } from '@/lib/api'
import type { Analysis, Health, PlatformStatus } from '@/types/api'

// Governance views load on first use, keeping the generate workspace lean.
const RuleLibraryView = lazy(() =>
  import('@/features/rule-library/RuleLibraryView').then((m) => ({ default: m.RuleLibraryView })),
)
const CoverageView = lazy(() =>
  import('@/features/coverage/CoverageView').then((m) => ({ default: m.CoverageView })),
)
const ActivityView = lazy(() =>
  import('@/features/activity/ActivityView').then((m) => ({ default: m.ActivityView })),
)
const PlatformView = lazy(() =>
  import('@/features/platform/PlatformView').then((m) => ({ default: m.PlatformView })),
)

const TABS = [
  { value: 'overview', label: 'Overview', icon: LayoutDashboard },
  { value: 'rules', label: 'Detection Rules', icon: Target },
  { value: 'testlab', label: 'Testing Lab', icon: FlaskConical },
  { value: 'intel', label: 'Attack Intelligence', icon: Crosshair },
  { value: 'validation', label: 'Validation', icon: ShieldCheck },
  { value: 'library', label: 'Library', icon: FolderOpen },
  { value: 'export', label: 'Export', icon: Braces },
]

export function App() {
  const reduced = useReducedMotion()
  const [input, setInput] = useState('')
  const [tab, setTab] = useState('overview')
  // Rule selection lives above the tabs so it survives tab switches and stays
  // in sync with the export tab.
  const [selectedRule, setSelectedRule] = useState(0)
  const [health, setHealth] = useState<Health | null>(null)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [view, setView] = useState<View>('generate')
  const [libraryRuleId, setLibraryRuleId] = useState<string | null>(null)
  const [platform, setPlatform] = useState<PlatformStatus | null>(null)

  const history = useHistory()
  const ai = useAIStatus()
  const aiProviders = useAIProviders()
  const activeAI = aiProviders.data?.active
  const investigations = useInvestigations()
  // Test cases live alongside the analysis so they are saved with it.
  const [testCases, setTestCases] = useState<TestCase[]>([])

  const onAnalysisSuccess = useCallback(
    (result: Analysis) => {
      history.add(result)
      setActiveId(`${result.generated_at}-${result.description.slice(0, 24)}`)
      setSelectedRule(0)
      setTab('overview')
      // A new analysis is not yet a saved investigation.
      investigations.setCurrentId(null)
    },
    [history, investigations],
  )

  const analysis = useAnalysis(onAnalysisSuccess)

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null))
  }, [])

  // Platform status (Splunk, provider, library counts) refreshes whenever a
  // governance view opens, so deploy buttons reflect the current backend.
  useEffect(() => {
    if (view === 'generate') return
    getPlatformStatus()
      .then(setPlatform)
      .catch(() => setPlatform(null))
  }, [view, activeAI])

  const openRule = useCallback((ruleId: string) => {
    setLibraryRuleId(ruleId)
    setView('library')
  }, [])

  const generateFor = useCallback((scenario: string) => {
    setInput(scenario)
    setView('generate')
  }, [])

  const handleNewAnalysis = useCallback(() => {
    analysis.reset()
    setInput('')
    setSelectedRule(0)
    setTab('overview')
    setActiveId(null)
    setTestCases([])
    investigations.setCurrentId(null)
    setView('generate')
  }, [analysis, investigations])

  const handleRestore = useCallback(
    (entry: HistoryEntry) => {
      analysis.restore(entry.analysis)
      setInput(entry.description)
      setSelectedRule(0)
      setTab('overview')
      setActiveId(entry.id)
      setView('generate')
    },
    [analysis],
  )

  const stale = analysis.analysis ? isStale(analysis.analysedInput, input) : false

  const panelMotion = reduced
    ? {}
    : {
        initial: { opacity: 0, y: 6 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.28, ease: [0.22, 1, 0.36, 1] as const },
      }

  return (
    <Shell
      aiPhase={ai.phase}
      aiDetail={ai.status?.detail}
      health={health}
      history={history.entries}
      onNewAnalysis={handleNewAnalysis}
      onRestore={handleRestore}
      onClearHistory={history.clear}
      hasAnalysis={analysis.analysis !== null}
      activeId={activeId}
      view={view}
      onNavigate={setView}
      aiControl={<AISwitcher state={aiProviders} />}
    >
      <Suspense
        fallback={<p className="text-xs text-ink-muted">Loading…</p>}
      >
      {view === 'library' && (
        <RuleLibraryView
          selectedId={libraryRuleId}
          onSelect={setLibraryRuleId}
          splunk={platform?.splunk ?? null}
        />
      )}
      {view === 'coverage' && <CoverageView onGenerate={generateFor} />}
      {view === 'activity' && <ActivityView onOpenRule={openRule} />}
      {view === 'platform' && (
        <PlatformView
          status={platform}
          aiProviders={aiProviders}
          onSplunkChecked={(splunk) =>
            setPlatform((current) => (current ? { ...current, splunk } : current))
          }
        />
      )}
      </Suspense>
      <div className={view === 'generate' ? 'space-y-5' : 'hidden'}>
        <AttackInput
          value={input}
          onChange={setInput}
          onGenerate={() => void analysis.run(input)}
          loading={analysis.loading}
          error={analysis.error}
          onDismissError={analysis.dismissError}
        />

        <AnimatePresence mode="wait">
          {analysis.analysis && (
            <motion.div
              key="results"
              initial={reduced ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={reduced ? { opacity: 0 } : { opacity: 0, y: -6 }}
              transition={reduced ? { duration: 0 } : { duration: 0.34, ease: [0.22, 1, 0.36, 1] }}
              className="space-y-5"
            >
              {stale && (
                <div className="flex items-start gap-2.5 rounded-xl border border-warn/30 bg-warn-soft px-3.5 py-3">
                  <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warn" />
                  <p className="text-xs leading-relaxed text-warn">
                    The description has changed since these results were generated. Generate again
                    to refresh them.
                  </p>
                </div>
              )}

              <Tabs value={tab} onValueChange={setTab}>
                <TabsList aria-label="Analysis results">
                  {TABS.map(({ value, label, icon: Icon }) => (
                    <TabsTrigger key={value} value={value}>
                      <span className="flex items-center gap-1.5">
                        <Icon className="size-3.5" aria-hidden />
                        {label}
                      </span>
                    </TabsTrigger>
                  ))}
                </TabsList>

                <TabsContent value="overview">
                  <motion.div key={`overview-${activeId}`} {...panelMotion}>
                    <OverviewTab analysis={analysis.analysis} />
                  </motion.div>
                </TabsContent>
                <TabsContent value="rules">
                  <motion.div key={`rules-${activeId}`} {...panelMotion}>
                    <RulesTab
                      analysis={analysis.analysis}
                      selectedIndex={selectedRule}
                      onSelect={setSelectedRule}
                      onOpenRule={openRule}
                    />
                  </motion.div>
                </TabsContent>
                <TabsContent value="testlab">
                  <motion.div key={`testlab-${activeId}`} {...panelMotion}>
                    <TestLabTab
                      analysis={analysis.analysis}
                      selectedIndex={selectedRule}
                      testCases={testCases}
                      onTestCasesChange={setTestCases}
                    />
                  </motion.div>
                </TabsContent>
                <TabsContent value="intel">
                  <motion.div key={`intel-${activeId}`} {...panelMotion}>
                    <IntelTab analysis={analysis.analysis} />
                  </motion.div>
                </TabsContent>
                <TabsContent value="validation">
                  <motion.div key={`validation-${activeId}`} {...panelMotion}>
                    <ValidationTab analysis={analysis.analysis} selectedIndex={selectedRule} />
                  </motion.div>
                </TabsContent>
                <TabsContent value="library">
                  <motion.div key={`library-${activeId}`} {...panelMotion}>
                    <LibraryPanel
                      store={investigations}
                      canSave={analysis.analysis !== null}
                      defaultTitle={analysis.analysis.description.slice(0, 80)}
                      buildPayload={() => ({
                        schema: 1,
                        analysis: analysis.analysis,
                        selected_rule: selectedRule,
                        test_cases: testCases,
                      })}
                      onOpen={(record) => {
                        const payload = record.payload as {
                          analysis?: Analysis
                          selected_rule?: number
                          test_cases?: TestCase[]
                        }
                        if (payload.analysis) {
                          analysis.restore(payload.analysis)
                          setInput(payload.analysis.description)
                          setActiveId(record.id)
                        }
                        setSelectedRule(payload.selected_rule ?? 0)
                        setTestCases(payload.test_cases ?? [])
                        setTab('overview')
                      }}
                    />
                  </motion.div>
                </TabsContent>
                <TabsContent value="export">
                  <motion.div key={`export-${activeId}`} {...panelMotion}>
                    <ExportTab analysis={analysis.analysis} selectedIndex={selectedRule} />
                  </motion.div>
                </TabsContent>
              </Tabs>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Remounts on an AI switch so its status reflects the new provider. */}
        <CopilotPanel
          key={activeAI ?? 'none'}
          analysis={analysis.analysis}
          selectedIndex={selectedRule}
        />

        <AIPanel description={input} phase={ai.phase} onRecheck={() => void ai.check(true)} />
      </div>
    </Shell>
  )
}

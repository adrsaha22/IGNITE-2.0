import { useCallback, useEffect, useState } from 'react'
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
import { Shell } from './Shell'
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
import { useHistory, type HistoryEntry } from '@/hooks/useHistory'
import { useReducedMotion } from '@/lib/motion'
import { getHealth } from '@/lib/api'
import type { Analysis, Health } from '@/types/api'

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

  const history = useHistory()
  const ai = useAIStatus()
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

  const handleNewAnalysis = useCallback(() => {
    analysis.reset()
    setInput('')
    setSelectedRule(0)
    setTab('overview')
    setActiveId(null)
    setTestCases([])
    investigations.setCurrentId(null)
  }, [analysis, investigations])

  const handleRestore = useCallback(
    (entry: HistoryEntry) => {
      analysis.restore(entry.analysis)
      setInput(entry.description)
      setSelectedRule(0)
      setTab('overview')
      setActiveId(entry.id)
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
    >
      <div className="space-y-5">
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
                    <ValidationTab analysis={analysis.analysis} />
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

        <CopilotPanel analysis={analysis.analysis} selectedIndex={selectedRule} />

        <AIPanel description={input} phase={ai.phase} onRecheck={() => void ai.check(true)} />
      </div>
    </Shell>
  )
}

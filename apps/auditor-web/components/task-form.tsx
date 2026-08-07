'use client'

import { useState, useEffect, useRef, useMemo } from 'react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Loader2, ArrowUp, Settings, X, Cable, Users, Globe, Monitor, AlertCircle } from 'lucide-react'
import { Claude, Codex, Copilot, Cursor, Gemini, OpenCode, AresLogo } from '@/components/logos'
import { setInstallDependencies, setMaxDuration, setKeepAlive, setEnableBrowser } from '@/lib/utils/cookies'
import { useConnectors } from '@/components/connectors-provider'
import { ConnectorDialog } from '@/components/connectors/manage-connectors'
import { useAtom, useAtomValue, useSetAtom } from 'jotai'
import { taskPromptAtom } from '@/lib/atoms/task'
import { lastSelectedAgentAtom, lastSelectedModelAtomFamily } from '@/lib/atoms/agent-selection'
import { githubReposAtomFamily } from '@/lib/atoms/github-cache'
import { useSearchParams } from 'next/navigation'
import { LM_STUDIO_AGENT, formatLmStudioModelLabel } from '@/lib/agents/lmstudio-ui'

interface GitHubRepo {
  name: string
  full_name: string
  description: string
  private: boolean
  clone_url: string
  language: string
}

// Wording follows the vulnerability classes the engine actually reasons about
// (see docs/POC-1-SPEC.md), so a first prompt lands on supported ground.
const EXAMPLE_PROMPTS = [
  {
    label: 'Audit signer checks',
    prompt:
      'Audit every instruction handler for missing signer checks. For each one, name the account that should be a signer and show the handler it reaches.',
  },
  {
    label: 'Find unchecked CPIs',
    prompt:
      'Find arbitrary CPI vulnerabilities: any cross-program invocation where the target program ID is not validated against an expected address.',
  },
  {
    label: 'Review PDA seeds',
    prompt:
      'Review PDA derivation across the program. Flag seeds that let one account impersonate another, and any bump that is not canonical.',
  },
] as const

interface TaskFormProps {
  onSubmit: (data: {
    prompt: string
    repoUrl: string
    selectedAgent: string
    selectedModel: string
    selectedModels?: string[]
    installDependencies: boolean
    maxDuration: number
    keepAlive: boolean
    enableBrowser: boolean
  }) => void
  isSubmitting: boolean
  selectedOwner: string
  selectedRepo: string
  /** Validation the parent owns (repo selection), surfaced inline instead of as a toast. */
  submitError?: string | null
  initialInstallDependencies?: boolean
  initialMaxDuration?: number
  initialKeepAlive?: boolean
  initialEnableBrowser?: boolean
  maxSandboxDuration?: number
}

const CODING_AGENTS_BASE = [
  { value: 'multi-agent', label: 'Compare', icon: Users, isLogo: false },
  { value: 'divider', label: '', icon: () => null, isLogo: false, isDivider: true },
  { value: 'claude', label: 'Claude', icon: Claude, isLogo: true },
  { value: 'codex', label: 'Codex', icon: Codex, isLogo: true },
  { value: 'copilot', label: 'Copilot', icon: Copilot, isLogo: true },
  { value: 'cursor', label: 'Cursor', icon: Cursor, isLogo: true },
  { value: 'gemini', label: 'Gemini', icon: Gemini, isLogo: true },
  { value: 'opencode', label: 'opencode', icon: OpenCode, isLogo: true },
] as const

function buildCodingAgents(showLmStudio: boolean) {
  if (!showLmStudio) {
    return CODING_AGENTS_BASE
  }
  return [
    CODING_AGENTS_BASE[0],
    CODING_AGENTS_BASE[1],
    { value: LM_STUDIO_AGENT, label: 'Local (LM Studio)', icon: Monitor, isLogo: false },
    ...CODING_AGENTS_BASE.slice(2),
  ]
}

// Model options for each agent
const AGENT_MODELS = {
  claude: [
    { value: 'claude-sonnet-4-5', label: 'Sonnet 4.5' },
    { value: 'anthropic/claude-opus-4.6', label: 'Opus 4.6' },
    { value: 'claude-haiku-4-5', label: 'Haiku 4.5' },
  ],
  codex: [
    { value: 'openai/gpt-5.1', label: 'GPT-5.1' },
    { value: 'openai/gpt-5.1-codex', label: 'GPT-5.1-Codex' },
    { value: 'openai/gpt-5.1-codex-mini', label: 'GPT-5.1-Codex mini' },
    { value: 'openai/gpt-5', label: 'GPT-5' },
    { value: 'gpt-5-codex', label: 'GPT-5-Codex' },
    { value: 'openai/gpt-5-mini', label: 'GPT-5 mini' },
    { value: 'openai/gpt-5-nano', label: 'GPT-5 nano' },
    { value: 'gpt-5-pro', label: 'GPT-5 pro' },
    { value: 'openai/gpt-4.1', label: 'GPT-4.1' },
  ],
  copilot: [
    { value: 'claude-sonnet-4.5', label: 'Sonnet 4.5' },
    { value: 'claude-sonnet-4', label: 'Sonnet 4' },
    { value: 'claude-haiku-4.5', label: 'Haiku 4.5' },
    { value: 'gpt-5', label: 'GPT-5' },
  ],
  cursor: [
    { value: 'auto', label: 'Auto' },
    { value: 'composer-1', label: 'Composer' },
    { value: 'sonnet-4.5', label: 'Sonnet 4.5' },
    { value: 'sonnet-4.5-thinking', label: 'Sonnet 4.5 Thinking' },
    { value: 'gpt-5', label: 'GPT-5' },
    { value: 'gpt-5-codex', label: 'GPT-5 Codex' },
    { value: 'opus-4.5', label: 'Opus 4.5' },
    { value: 'opus-4.1', label: 'Opus 4.1' },
    { value: 'grok', label: 'Grok' },
  ],
  gemini: [
    { value: 'gemini-3-pro-preview', label: 'Gemini 3 Pro Preview' },
    { value: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro' },
    { value: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash' },
  ],
  opencode: [
    { value: 'gpt-5', label: 'GPT-5' },
    { value: 'gpt-5-mini', label: 'GPT-5 mini' },
    { value: 'gpt-5-nano', label: 'GPT-5 nano' },
    { value: 'gpt-4.1', label: 'GPT-4.1' },
    { value: 'claude-sonnet-4-5', label: 'Sonnet 4.5' },
    { value: 'claude-opus-4-5', label: 'Opus 4.5' },
    { value: 'claude-haiku-4-5', label: 'Haiku 4.5' },
  ],
  lmstudio: [] as { value: string; label: string }[],
} as const

// Default models for each agent
const DEFAULT_MODELS = {
  claude: 'claude-sonnet-4-5',
  codex: 'openai/gpt-5.1',
  copilot: 'claude-sonnet-4.5',
  cursor: 'auto',
  gemini: 'gemini-3-pro-preview',
  opencode: 'gpt-5',
  lmstudio: '',
} as const

// API key requirements for each agent
const AGENT_API_KEY_REQUIREMENTS: Record<string, Provider[]> = {
  claude: ['anthropic'],
  codex: ['aigateway'], // Uses AI Gateway for OpenAI proxy
  copilot: [], // Uses user's GitHub account token automatically
  cursor: ['cursor'],
  gemini: ['gemini'],
  opencode: [], // Will be determined dynamically based on selected model
  lmstudio: [], // Uses server LM_STUDIO_MODEL — no user API key
}

type Provider = 'openai' | 'gemini' | 'cursor' | 'anthropic' | 'aigateway'

// Helper to determine which API key is needed for opencode based on model
const getOpenCodeRequiredKeys = (model: string): Provider[] => {
  // Check if it's an Anthropic model (claude models)
  if (model.includes('claude') || model.includes('sonnet') || model.includes('opus')) {
    return ['anthropic']
  }
  // Check if it's an OpenAI/GPT model (uses AI Gateway)
  if (model.includes('gpt')) {
    return ['aigateway']
  }
  // Fallback to both if we can't determine
  return ['aigateway', 'anthropic']
}

export function TaskForm({
  onSubmit,
  isSubmitting,
  selectedOwner,
  selectedRepo,
  submitError = null,
  initialInstallDependencies = false,
  initialMaxDuration = 300,
  initialKeepAlive = false,
  initialEnableBrowser = false,
  maxSandboxDuration = 300,
}: TaskFormProps) {
  const [prompt, setPrompt] = useAtom(taskPromptAtom)
  const [ownError, setOwnError] = useState<string | null>(null)
  // Parent-owned errors show until the parent clears them; own errors clear as the user edits.
  const formError = ownError ?? submitError
  const [savedAgent, setSavedAgent] = useAtom(lastSelectedAgentAtom)
  const [selectedAgent, setSelectedAgent] = useState(savedAgent || 'claude')
  const [selectedModel, setSelectedModel] = useState<string>(DEFAULT_MODELS.claude)
  const [selectedModels, setSelectedModels] = useState<string[]>([])
  const [repos, setRepos] = useAtom(githubReposAtomFamily(selectedOwner))
  const [, setLoadingRepos] = useState(false)

  // Options state - initialize with server values
  const [installDependencies, setInstallDependenciesState] = useState(initialInstallDependencies)
  const [maxDuration, setMaxDurationState] = useState(initialMaxDuration)
  const [keepAlive, setKeepAliveState] = useState(initialKeepAlive)
  const [enableBrowser, setEnableBrowserState] = useState(initialEnableBrowser)
  const [showMcpServersDialog, setShowMcpServersDialog] = useState(false)
  const [lmStudioAvailable, setLmStudioAvailable] = useState(false)
  const [lmStudioModels, setLmStudioModels] = useState<{ value: string; label: string }[]>([])

  const CODING_AGENTS = useMemo(() => buildCodingAgents(lmStudioAvailable), [lmStudioAvailable])

  const agentModelsByAgent = {
    ...AGENT_MODELS,
    lmstudio: lmStudioModels,
  }

  // Connectors state
  const { connectors } = useConnectors()

  // Ref for the textarea to focus it programmatically
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Wrapper functions to update both state and cookies
  const updateInstallDependencies = (value: boolean) => {
    setInstallDependenciesState(value)
    setInstallDependencies(value)
  }

  const updateMaxDuration = (value: number) => {
    setMaxDurationState(value)
    setMaxDuration(value)
  }

  const updateKeepAlive = (value: boolean) => {
    setKeepAliveState(value)
    setKeepAlive(value)
  }

  const updateEnableBrowser = (value: boolean) => {
    setEnableBrowserState(value)
    setEnableBrowser(value)
  }

  // Handle keyboard events in textarea
  const handleTextareaKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter') {
      // On desktop: Enter submits, Shift+Enter creates new line
      // On mobile: Enter creates new line, must use submit button
      const isMobile = typeof window !== 'undefined' && window.innerWidth < 768
      if (!isMobile && !e.shiftKey) {
        e.preventDefault()
        if (prompt.trim()) {
          // Find the form and submit it
          const form = e.currentTarget.closest('form')
          if (form) {
            form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
          }
        }
      }
      // For all other cases (mobile Enter, desktop Shift+Enter), let default behavior create new line
    }
  }

  // Get URL search params
  const searchParams = useSearchParams()

  // Load LM Studio availability from server env
  useEffect(() => {
    const loadLmStudioStatus = async () => {
      try {
        const response = await fetch('/api/llm/status')
        if (!response.ok) return
        const data = await response.json()
        const configured = Boolean(data.lmStudio?.configured && data.lmStudio?.model)
        if (configured && data.lmStudio.model) {
          // value = full model id (submitted as selectedModel); label = short display text
          const modelId = data.lmStudio.model as string
          const modelOption = {
            value: modelId,
            label: (data.lmStudio.modelLabel as string) || formatLmStudioModelLabel(modelId),
          }
          setLmStudioModels([modelOption])
          setLmStudioAvailable(true)
        }
      } catch {
        // LM Studio option stays hidden when status cannot be loaded
      }
    }
    loadLmStudioStatus()
  }, [])

  // Load saved agent, model, and options on mount, and focus the prompt input
  useEffect(() => {
    // Check URL params first
    const urlAgent = searchParams?.get('agent')
    const urlModel = searchParams?.get('model')

    if (
      urlAgent &&
      CODING_AGENTS.some((agent) => agent.value === urlAgent && !('isDivider' in agent && agent.isDivider))
    ) {
      setSelectedAgent(urlAgent)
      if (urlModel) {
        const agentModels = agentModelsByAgent[urlAgent as keyof typeof agentModelsByAgent]
        if (agentModels?.some((model) => model.value === urlModel)) {
          setSelectedModel(urlModel)
        }
      }
    } else if (savedAgent) {
      // Fall back to saved agent from Jotai atom
      if (CODING_AGENTS.some((agent) => agent.value === savedAgent && !('isDivider' in agent && agent.isDivider))) {
        setSelectedAgent(savedAgent)
      }
    }

    // Options are now initialized from server props, no need to load from cookies

    // Focus the prompt input when the component mounts
    if (textareaRef.current) {
      textareaRef.current.focus()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Get saved model atom for current agent
  const savedModelAtom = lastSelectedModelAtomFamily(selectedAgent)
  const savedModel = useAtomValue(savedModelAtom)
  const setSavedModel = useSetAtom(savedModelAtom)

  // Update model when agent changes
  useEffect(() => {
    if (selectedAgent) {
      // Clear selectedModels when switching away from multi-agent
      if (selectedAgent !== 'multi-agent') {
        setSelectedModels([])
      }

      // Load saved model for this agent or use default
      const agentModels = agentModelsByAgent[selectedAgent as keyof typeof agentModelsByAgent]
      if (savedModel && agentModels?.some((model) => model.value === savedModel)) {
        setSelectedModel(savedModel)
      } else {
        const defaultModel = DEFAULT_MODELS[selectedAgent as keyof typeof DEFAULT_MODELS]
        if (defaultModel) {
          setSelectedModel(defaultModel)
        }
      }
    }
  }, [selectedAgent, savedModel, lmStudioModels])

  // Default LM Studio model once loaded
  useEffect(() => {
    if (selectedAgent === LM_STUDIO_AGENT && lmStudioModels[0] && selectedModel !== lmStudioModels[0].value) {
      setSelectedModel(lmStudioModels[0].value)
    }
  }, [selectedAgent, lmStudioModels, selectedModel])

  // Fall back if LM Studio agent was saved but server is not configured
  useEffect(() => {
    if (selectedAgent === LM_STUDIO_AGENT && !lmStudioAvailable && lmStudioModels.length === 0) {
      setSelectedAgent(savedAgent && savedAgent !== LM_STUDIO_AGENT ? savedAgent : 'claude')
    }
  }, [selectedAgent, lmStudioAvailable, lmStudioModels.length, savedAgent])

  // Fetch repositories when owner changes
  useEffect(() => {
    if (!selectedOwner) {
      setRepos(null)
      return
    }

    const fetchRepos = async () => {
      setLoadingRepos(true)
      try {
        // Check cache first (repos is from the atom)
        if (repos && repos.length > 0) {
          setLoadingRepos(false)
          return
        }

        const response = await fetch(`/api/github/repos?owner=${selectedOwner}`)
        if (response.ok) {
          const reposList = await response.json()
          setRepos(reposList)
        }
      } catch (error) {
        console.error('Error fetching repositories:', error)
      } finally {
        setLoadingRepos(false)
      }
    }

    fetchRepos()
  }, [selectedOwner, repos, setRepos])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setOwnError(null)

    if (!prompt.trim()) {
      setOwnError('Describe the audit you want to run before starting.')
      textareaRef.current?.focus()
      return
    }

    // Validate that multi-agent mode has at least one model selected
    if (selectedAgent === 'multi-agent' && selectedModels.length === 0) {
      setOwnError('Multi-agent mode needs at least one model selected.')
      return
    }

    // If owner/repo not selected, let parent handle it (will show sign-in if needed)
    // Don't clear localStorage here - user might need to sign in and come back
    if (!selectedOwner || !selectedRepo) {
      onSubmit({
        prompt: prompt.trim(),
        repoUrl: '',
        selectedAgent,
        selectedModel,
        selectedModels: selectedAgent === 'multi-agent' ? selectedModels : undefined,
        installDependencies,
        maxDuration,
        keepAlive,
        enableBrowser,
      })
      return
    }

    // Check if API key is required and available for the selected agent and model
    // Skip this check if we don't have repo data (likely not signed in) or if multi-agent mode
    const selectedRepoData = repos?.find((repo) => repo.name === selectedRepo)

    if (selectedRepoData && selectedAgent !== 'multi-agent') {
      try {
        const response = await fetch(`/api/api-keys/check?agent=${selectedAgent}&model=${selectedModel}`)
        const data = await response.json()

        if (!data.hasKey) {
          // Show error message with provider name
          const providerNames: Record<string, string> = {
            anthropic: 'Anthropic',
            openai: 'OpenAI',
            cursor: 'Cursor',
            gemini: 'Gemini',
            aigateway: 'AI Gateway',
            lmstudio: 'LM Studio',
          }
          const providerName = providerNames[data.provider] || data.provider

          setOwnError(
            `${providerName} API key required. Add it under your avatar → API keys to run ${data.agentName} with this model.`,
          )
          return
        }
      } catch (error) {
        console.error('Error checking API key:', error)
        // Don't show error toast - might just be not authenticated, let parent handle it
      }
    }

    onSubmit({
      prompt: prompt.trim(),
      repoUrl: selectedRepoData?.clone_url || '',
      selectedAgent,
      selectedModel,
      selectedModels: selectedAgent === 'multi-agent' ? selectedModels : undefined,
      installDependencies,
      maxDuration,
      keepAlive,
      enableBrowser,
    })
  }

  return (
    <div className="w-full max-w-2xl">
      <div className="text-center mb-8">
        <div className="flex justify-center mb-5">
          <AresLogo height={44} priority className="rounded-md" />
        </div>
        <p className="text-lg text-muted-foreground mb-2">
          Run and monitor Solana security audits — static analysis, on-chain posture, and LLM-assisted review with
          persistent knowledge recall.
        </p>
      </div>

      <form onSubmit={handleSubmit}>
        {/* Focus is indicated on this container: the inner controls suppress their own
            rings so the composite input reads as a single field. */}
        <div className="relative border rounded-2xl shadow-sm overflow-hidden bg-muted/30 cursor-text focus-within:ring-2 focus-within:ring-ring focus-within:border-ring">
          {/* Prompt Input */}
          <div className="relative bg-transparent">
            <Textarea
              ref={textareaRef}
              id="prompt"
              placeholder="Describe the audit you want — which program, which instructions, what you're worried about."
              value={prompt}
              onChange={(e) => {
                setPrompt(e.target.value)
                if (ownError) setOwnError(null)
              }}
              onKeyDown={handleTextareaKeyDown}
              disabled={isSubmitting}
              required
              aria-invalid={formError ? true : undefined}
              aria-describedby={formError ? 'task-form-error' : undefined}
              rows={4}
              className="w-full border-0 resize-none focus-visible:ring-0 focus-visible:ring-offset-0 p-4 text-base !bg-transparent shadow-none!"
            />
          </div>

          {/* Agent Selection */}
          <div className="p-4">
            <div className="flex items-center justify-between gap-2">
              {/* Left side: Agent, Model, and Option Chips */}
              <div className="flex items-center gap-2 flex-1 min-w-0">
                {/* Agent Selection - Icon only on mobile, minimal width */}
                <Select
                  value={selectedAgent}
                  onValueChange={(value) => {
                    setSelectedAgent(value)
                    // Save to Jotai atom immediately
                    setSavedAgent(value)
                  }}
                  disabled={isSubmitting}
                >
                  <SelectTrigger className="w-auto sm:min-w-[120px] border-0 bg-transparent shadow-none focus:ring-0 h-8 shrink-0">
                    <SelectValue placeholder="Agent">
                      {selectedAgent &&
                        (() => {
                          const agent = CODING_AGENTS.find((a) => a.value === selectedAgent)
                          return agent ? (
                            <div className="flex items-center gap-2">
                              <agent.icon className="w-4 h-4" />
                              <span className="hidden sm:inline">{agent.label}</span>
                            </div>
                          ) : null
                        })()}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {CODING_AGENTS.map((agent) => {
                      if ('isDivider' in agent && agent.isDivider) {
                        return <div key={agent.value} className="h-px bg-border my-1" />
                      }
                      return (
                        <SelectItem key={agent.value} value={agent.value}>
                          <div className="flex items-center gap-2">
                            <agent.icon className="w-4 h-4" />
                            <span>{agent.label}</span>
                          </div>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>

                {/* Model Selection - Fills available width on mobile */}
                {selectedAgent === 'multi-agent' ? (
                  <Select value="multi-select" onValueChange={() => {}} disabled={isSubmitting}>
                    <SelectTrigger className="flex-1 sm:flex-none sm:w-auto sm:min-w-[140px] border-0 bg-transparent shadow-none focus:ring-0 h-8 min-w-0">
                      <SelectValue>
                        {selectedModels.length === 0 ? 'Select models' : `${selectedModels.length} Selected`}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      {CODING_AGENTS.filter(
                        (agent) =>
                          !('isDivider' in agent && agent.isDivider) &&
                          agent.value !== 'multi-agent' &&
                          agent.value !== LM_STUDIO_AGENT,
                      ).map((agent) => (
                        <div key={agent.value}>
                          <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">{agent.label}</div>
                          {agentModelsByAgent[agent.value as keyof typeof agentModelsByAgent]?.map((model) => {
                            const fullValue = `${agent.value}:${model.value}`
                            const isSelected = selectedModels.includes(fullValue)
                            return (
                              <div
                                key={fullValue}
                                className="relative flex cursor-pointer select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50"
                                onClick={(e) => {
                                  e.preventDefault()
                                  setSelectedModels((prev) =>
                                    isSelected ? prev.filter((m) => m !== fullValue) : [...prev, fullValue],
                                  )
                                }}
                              >
                                <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
                                  {isSelected && (
                                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth={2}
                                        d="M5 13l4 4L19 7"
                                      />
                                    </svg>
                                  )}
                                </span>
                                {model.label}
                              </div>
                            )
                          })}
                        </div>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Select
                    value={selectedModel}
                    onValueChange={(value) => {
                      setSelectedModel(value)
                      // Save to Jotai atom immediately
                      setSavedModel(value)
                    }}
                    disabled={isSubmitting}
                  >
                    <SelectTrigger className="flex-1 sm:flex-none sm:w-auto sm:min-w-[140px] border-0 bg-transparent shadow-none focus:ring-0 h-8 min-w-0">
                      <SelectValue placeholder="Model" className="truncate" />
                    </SelectTrigger>
                    <SelectContent>
                      {agentModelsByAgent[selectedAgent as keyof typeof agentModelsByAgent]?.map((model) => (
                        <SelectItem key={model.value} value={model.value}>
                          {model.label}
                        </SelectItem>
                      )) || []}
                    </SelectContent>
                  </Select>
                )}

                {/* Option Chips - Only visible on desktop */}
                {(!installDependencies || maxDuration !== maxSandboxDuration || keepAlive) && (
                  <div className="hidden sm:flex items-center gap-2 flex-wrap">
                    {!installDependencies && (
                      <Badge variant="secondary" className="text-xs h-6 px-2 gap-1 bg-transparent border-0">
                        Skip Install
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-3 w-3 p-0 hover:bg-transparent"
                          onClick={(e) => {
                            e.stopPropagation()
                            updateInstallDependencies(true)
                          }}
                        >
                          <X className="h-2 w-2" />
                        </Button>
                      </Badge>
                    )}
                    {maxDuration !== maxSandboxDuration && (
                      <Badge variant="secondary" className="text-xs h-6 px-2 gap-1 bg-transparent border-0">
                        {maxDuration}m
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-3 w-3 p-0 hover:bg-transparent"
                          onClick={(e) => {
                            e.stopPropagation()
                            updateMaxDuration(maxSandboxDuration)
                          }}
                        >
                          <X className="h-2 w-2" />
                        </Button>
                      </Badge>
                    )}
                    {keepAlive && (
                      <Badge variant="secondary" className="text-xs h-6 px-2 gap-1 bg-transparent border-0">
                        Keep Alive
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-3 w-3 p-0 hover:bg-transparent"
                          onClick={(e) => {
                            e.stopPropagation()
                            updateKeepAlive(false)
                          }}
                        >
                          <X className="h-2 w-2" />
                        </Button>
                      </Badge>
                    )}
                  </div>
                )}
              </div>

              {/* Right side: Action Icons and Submit Button */}
              <div className="flex items-center gap-2 shrink-0">
                {/* Buttons */}
                <div className="flex items-center gap-2">
                  <TooltipProvider delayDuration={1500} skipDelayDuration={1500}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="rounded-full h-8 w-8 p-0 relative"
                          onClick={() => updateEnableBrowser(!enableBrowser)}
                        >
                          <Globe className="h-4 w-4" />
                          {enableBrowser && (
                            <span className="absolute top-1 right-1 h-1.5 w-1.5 rounded-full bg-green-500" />
                          )}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Agent Browser</p>
                      </TooltipContent>
                    </Tooltip>

                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="rounded-full h-8 w-8 p-0 relative"
                          onClick={() => setShowMcpServersDialog(true)}
                        >
                          <Cable className="h-4 w-4" />
                          {connectors.filter((c) => c.status === 'connected').length > 0 && (
                            <Badge
                              variant="secondary"
                              className="absolute -top-1 -right-1 h-4 min-w-4 p-0 flex items-center justify-center text-[10px] rounded-full"
                            >
                              {connectors.filter((c) => c.status === 'connected').length}
                            </Badge>
                          )}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>MCP Servers</p>
                      </TooltipContent>
                    </Tooltip>

                    <DropdownMenu>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <DropdownMenuTrigger asChild>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="rounded-full h-8 w-8 p-0 relative"
                            >
                              <Settings className="h-4 w-4" />
                              {(() => {
                                const customOptionsCount = [
                                  !installDependencies,
                                  maxDuration !== maxSandboxDuration,
                                  keepAlive,
                                ].filter(Boolean).length
                                return customOptionsCount > 0 ? (
                                  <Badge
                                    variant="secondary"
                                    className="absolute -top-1 -right-1 h-4 min-w-4 p-0 flex items-center justify-center text-[10px] rounded-full sm:hidden"
                                  >
                                    {customOptionsCount}
                                  </Badge>
                                ) : null
                              })()}
                            </Button>
                          </DropdownMenuTrigger>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>Task Options</p>
                        </TooltipContent>
                      </Tooltip>
                      <DropdownMenuContent className="w-72" align="end">
                        <DropdownMenuLabel>Task Options</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <div className="p-2 space-y-4">
                          <div className="flex items-center space-x-2">
                            <Checkbox
                              id="install-deps"
                              checked={installDependencies}
                              onCheckedChange={(checked) => updateInstallDependencies(checked === true)}
                            />
                            <Label
                              htmlFor="install-deps"
                              className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                            >
                              Install Dependencies?
                            </Label>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="max-duration" className="text-sm font-medium">
                              Maximum Duration
                            </Label>
                            <Select
                              value={maxDuration.toString()}
                              onValueChange={(value) => updateMaxDuration(parseInt(value))}
                            >
                              <SelectTrigger id="max-duration" className="w-full h-8">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="5">5 minutes</SelectItem>
                                <SelectItem value="10">10 minutes</SelectItem>
                                <SelectItem value="15">15 minutes</SelectItem>
                                <SelectItem value="30">30 minutes</SelectItem>
                                <SelectItem value="45">45 minutes</SelectItem>
                                <SelectItem value="60">1 hour</SelectItem>
                                <SelectItem value="120">2 hours</SelectItem>
                                <SelectItem value="180">3 hours</SelectItem>
                                <SelectItem value="240">4 hours</SelectItem>
                                <SelectItem value="300">5 hours</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="space-y-2">
                            <div className="flex items-center space-x-2">
                              <Checkbox
                                id="keep-alive"
                                checked={keepAlive}
                                onCheckedChange={(checked) => updateKeepAlive(checked === true)}
                              />
                              <Label
                                htmlFor="keep-alive"
                                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                              >
                                Keep Alive ({maxSandboxDuration}m max)
                              </Label>
                            </div>
                            <p className="text-xs text-muted-foreground pl-6">Keep sandbox running after completion.</p>
                          </div>
                        </div>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TooltipProvider>

                  <Button
                    type="submit"
                    disabled={isSubmitting || !prompt.trim()}
                    size="sm"
                    aria-label={isSubmitting ? 'Starting audit' : 'Run audit'}
                    title={
                      !prompt.trim()
                        ? 'Describe the audit you want to run first'
                        : isSubmitting
                          ? 'Starting audit…'
                          : 'Run audit'
                    }
                    className="rounded-full h-8 gap-1.5 px-2 sm:px-3"
                  >
                    {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowUp className="h-4 w-4" />}
                    <span className="hidden sm:inline">{isSubmitting ? 'Starting…' : 'Run audit'}</span>
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {formError && (
          <p id="task-form-error" role="alert" className="mt-2 flex items-start gap-1.5 text-xs text-destructive">
            <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-px" />
            {formError}
          </p>
        )}

        {/* First-run guidance: an empty composer says nothing about what a good prompt
            looks like. Clicking one fills the box so the user can edit rather than invent. */}
        {!prompt.trim() && !isSubmitting && (
          <div className="mt-3 flex flex-wrap justify-center gap-1.5">
            {EXAMPLE_PROMPTS.map((example) => (
              <button
                key={example.label}
                type="button"
                onClick={() => {
                  setPrompt(example.prompt)
                  setOwnError(null)
                  textareaRef.current?.focus()
                }}
                className="rounded-full border px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              >
                {example.label}
              </button>
            ))}
          </div>
        )}

        {/* Multi-Agent Info */}
        {selectedAgent === 'multi-agent' && selectedModels.length > 0 && (
          <div className="mt-2 text-xs text-muted-foreground text-center">
            This will create {selectedModels.length} separate task{selectedModels.length > 1 ? 's' : ''} (one for each
            selected model)
          </div>
        )}
      </form>

      <ConnectorDialog open={showMcpServersDialog} onOpenChange={setShowMcpServersDialog} />
    </div>
  )
}

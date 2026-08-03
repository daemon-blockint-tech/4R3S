import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useHealth } from '@/hooks/useHealth'
import { cn } from '@/lib/utils'

/**
 * Terminal — a macOS Terminal.app-flavoured console for ARES.
 *
 * Default mode is a chat with the model behind ARES (POST /api/llm/chat).
 * Allowlisted tools run through the audited execution gate (POST /api/tools/execute)
 * via `!<cmd>` or `/run <cmd>`. Built-ins (`/help`, `/clear`, `/tools`, `/status`)
 * never leave the browser. Everything the backend does still passes the approval policy.
 */

const MONO =
  '"SF Mono", SFMono-Regular, Menlo, Monaco, "Cascadia Code", "Roboto Mono", Consolas, "Courier New", monospace'

const PROMPT_USER = 'operator@ares'
const PROMPT_PATH = '~'

type LineKind = 'command' | 'chat' | 'tool' | 'system' | 'error'

interface Line {
  id: number
  kind: LineKind
  /** Raw text (command echo for `command`, body for everything else). */
  text: string
  /** Right-aligned status chip, e.g. `142ms · ok`. */
  meta?: string
}

interface ToolResult {
  success: boolean
  output: string
  error?: string
  duration?: number
}

interface LlmStatus {
  connected: boolean
  provider?: string
  model?: string
  hasApiKey?: boolean
}

const HELP = `ARES terminal — commands
  <text>            talk to the model behind ARES
  !<cmd>            run an allowlisted tool through the execution gate
  /run <cmd>        same as !<cmd>
  /recon <target>   quick recon scan (dns + nmap) through the gate
  /tools            list allowlisted binaries
  /status           show the LLM connection
  /clear  (or clear) wipe the screen
  /help   (or help)  show this help

Every backend action is audited and still obeys the approval policy.`

let LINE_SEQ = 0
function nextId() {
  return ++LINE_SEQ
}

export function TerminalPage() {
  const [lines, setLines] = useState<Line[]>([
    {
      id: nextId(),
      kind: 'system',
      text: 'ARES terminal ready. Type a message to chat, or `/help` for commands.',
    },
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<string[]>([])
  const [histIndex, setHistIndex] = useState(-1)

  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const { state } = useHealth()
  const llmStatus = useQuery({
    queryKey: ['llm-status'],
    queryFn: () => api.get<LlmStatus>('/api/llm/status'),
    refetchInterval: 15_000,
    retry: false,
  })
  const tools = useQuery({
    queryKey: ['tools'],
    queryFn: () => api.get<{ tools: string[] }>('/api/tools'),
    staleTime: 60_000,
  })

  const push = useCallback((line: Omit<Line, 'id'>) => {
    setLines((prev) => [...prev, { id: nextId(), ...line }])
  }, [])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [lines, busy])

  const runChat = useCallback(
    async (message: string) => {
      setBusy(true)
      try {
        const data = await api.post<{ success: boolean; response: string }>('/api/llm/chat', {
          message,
        })
        push({ kind: 'chat', text: data.response?.trim() || '(empty response)' })
      } catch (e) {
        push({ kind: 'error', text: e instanceof Error ? e.message : String(e) })
      } finally {
        setBusy(false)
      }
    },
    [push],
  )

  const runTool = useCallback(
    async (command: string) => {
      if (!command) {
        push({ kind: 'error', text: 'usage: !<command>  (e.g. !nmap -F scanme.nmap.org)' })
        return
      }
      setBusy(true)
      try {
        const result = await api.post<ToolResult>('/api/tools/execute', { command })
        push({
          kind: result.success ? 'tool' : 'error',
          text: result.output || result.error || '(no output)',
          meta: `${result.duration != null ? `${result.duration}ms · ` : ''}${result.success ? 'ok' : 'fail'}`,
        })
      } catch (e) {
        push({ kind: 'error', text: e instanceof Error ? e.message : String(e) })
      } finally {
        setBusy(false)
      }
    },
    [push],
  )

  const runRecon = useCallback(
    async (target: string) => {
      if (!target) {
        push({ kind: 'error', text: 'usage: /recon <target>  (e.g. /recon scanme.nmap.org)' })
        return
      }
      setBusy(true)
      try {
        const result = await api.post<{
          success: boolean
          target: string
          results?: { dns?: unknown; ports?: unknown }
        }>('/api/tools/recon', { target, scan_type: 'quick' })
        const dns = (result.results?.dns as { output?: string })?.output ?? JSON.stringify(result.results?.dns)
        const ports = (result.results?.ports as { output?: string })?.output ?? JSON.stringify(result.results?.ports)
        push({
          kind: 'tool',
          text: `recon ${result.target}\n\n[dns]\n${dns || '(none)'}\n\n[ports]\n${ports || '(none)'}`,
          meta: result.success ? 'ok' : 'fail',
        })
      } catch (e) {
        push({ kind: 'error', text: e instanceof Error ? e.message : String(e) })
      } finally {
        setBusy(false)
      }
    },
    [push],
  )

  const clear = useCallback(() => setLines([]), [])

  const submit = useCallback(
    (raw: string) => {
      const value = raw.trim()
      // Echo the command with the prompt, always (even when blank, like a real shell).
      push({ kind: 'command', text: raw })
      if (value) {
        setHistory((h) => (h[h.length - 1] === value ? h : [...h, value]))
      }
      setHistIndex(-1)
      if (!value) return

      const lower = value.toLowerCase()
      if (lower === 'clear' || lower === '/clear') {
        clear()
        return
      }
      if (lower === 'help' || lower === '/help') {
        push({ kind: 'system', text: HELP })
        return
      }
      if (lower === '/tools') {
        const list = tools.data?.tools ?? []
        push({
          kind: 'system',
          text: list.length
            ? `allowlisted (${list.length}):\n${list.join('  ')}`
            : 'no allowlisted tools reported by /api/tools',
        })
        return
      }
      if (lower === '/status') {
        const s = llmStatus.data
        push({
          kind: 'system',
          text: s
            ? `llm: ${s.connected ? 'connected' : 'disconnected'}${s.provider ? ` · provider ${s.provider}` : ''}${s.model ? ` · model ${s.model}` : ''}`
            : 'llm status unavailable',
        })
        return
      }
      if (value.startsWith('!')) {
        void runTool(value.slice(1).trim())
        return
      }
      if (lower.startsWith('/run ') || lower === '/run') {
        void runTool(value.slice(4).trim())
        return
      }
      if (lower.startsWith('/recon ') || lower === '/recon') {
        void runRecon(value.slice(6).trim())
        return
      }
      void runChat(value)
    },
    [push, clear, runChat, runTool, runRecon, tools.data, llmStatus.data],
  )

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      if (busy) return
      submit(input)
      setInput('')
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (!history.length) return
      const idx = histIndex === -1 ? history.length - 1 : Math.max(0, histIndex - 1)
      setHistIndex(idx)
      setInput(history[idx])
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (histIndex === -1) return
      const idx = histIndex + 1
      if (idx >= history.length) {
        setHistIndex(-1)
        setInput('')
      } else {
        setHistIndex(idx)
        setInput(history[idx])
      }
      return
    }
    if (e.key === 'l' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      clear()
    }
  }

  const s = llmStatus.data
  const subtitle = useMemo(() => {
    if (s?.provider && s?.model) return `${s.provider} · ${s.model}`
    if (s?.connected) return 'llm connected'
    return '-zsh'
  }, [s])

  const online = state === 'llm' || (s?.connected ?? false)

  return (
    <div className="mx-auto flex h-[calc(100dvh-7rem)] max-w-5xl flex-col">
      <div
        className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-black/60 shadow-2xl ring-1 ring-white/5"
        style={{ backgroundColor: '#1e1e1e', fontFamily: MONO }}
        onClick={() => inputRef.current?.focus()}
      >
        {/* Title bar */}
        <div
          className="relative flex shrink-0 items-center gap-2 border-b border-black/40 px-3.5 py-2.5 select-none"
          style={{ backgroundColor: '#323233' }}
        >
          <div className="flex items-center gap-2">
            <TrafficLight color="#ff5f56" title="close" onClick={clear} />
            <TrafficLight color="#ffbd2e" title="minimize" />
            <TrafficLight color="#27c93f" title="zoom" />
          </div>
          <div className="pointer-events-none absolute inset-x-0 flex flex-col items-center justify-center">
            <span className="text-[12px] font-medium leading-tight text-neutral-300">
              Terminal — ARES
            </span>
            <span className="text-[10px] leading-tight text-neutral-500">{subtitle}</span>
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            <span
              className={cn(
                'size-2 rounded-full',
                online ? 'bg-[#27c93f]' : state === 'checking' ? 'animate-pulse bg-neutral-500' : 'bg-[#ff5f56]',
              )}
            />
            <span className="text-[10px] text-neutral-500">{online ? 'LLM ready' : 'offline'}</span>
          </div>
        </div>

        {/* Output */}
        <div
          ref={scrollRef}
          className="min-h-0 flex-1 overflow-y-auto px-4 py-3 text-[13px] leading-relaxed"
          style={{ color: '#e4e4e4' }}
        >
          {lines.map((line) => (
            <TerminalLine key={line.id} line={line} />
          ))}
          {busy && (
            <div className="flex items-center gap-2 py-0.5 text-neutral-500">
              <Spinner />
              <span>working…</span>
            </div>
          )}

          {/* Live prompt (inline input) */}
          {!busy && (
            <div className="flex flex-wrap items-baseline gap-x-2 py-0.5">
              <Prompt />
              <input
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={onKeyDown}
                autoFocus
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                aria-label="Terminal input"
                className="min-w-[8ch] flex-1 border-none bg-transparent p-0 text-[13px] text-neutral-100 caret-[#27c93f] outline-none placeholder:text-neutral-600"
                style={{ fontFamily: MONO }}
                placeholder="type a message, or /help"
              />
            </div>
          )}
        </div>
      </div>

      <p className="mt-2 px-1 text-center text-[11px] text-muted-foreground">
        Chat routes to <code className="font-mono">/api/llm/chat</code>. Prefix with{' '}
        <code className="font-mono">!</code> to run an allowlisted tool via{' '}
        <code className="font-mono">/api/tools/execute</code> — both audited, both gated by the
        approval policy. ↑/↓ recall history · ⌃L clears.
      </p>
    </div>
  )
}

function Prompt() {
  return (
    <span className="shrink-0 select-none">
      <span style={{ color: '#27c93f' }}>{PROMPT_USER}</span>
      <span className="text-neutral-500">:</span>
      <span style={{ color: '#569cd6' }}>{PROMPT_PATH}</span>
      <span className="text-neutral-400"> % </span>
    </span>
  )
}

function TerminalLine({ line }: { line: Line }) {
  if (line.kind === 'command') {
    return (
      <div className="flex flex-wrap items-baseline gap-x-2 py-0.5">
        <Prompt />
        <span className="whitespace-pre-wrap break-words text-neutral-100">{line.text}</span>
      </div>
    )
  }

  const color =
    line.kind === 'error'
      ? '#ff6b6b'
      : line.kind === 'tool'
        ? '#d7ba7d'
        : line.kind === 'system'
          ? '#7f7f7f'
          : '#e4e4e4'

  return (
    <div className="py-0.5">
      {line.meta && (
        <div className="mb-0.5 text-[10px] uppercase tracking-wider text-neutral-600">
          {line.meta}
        </div>
      )}
      <pre
        className="m-0 whitespace-pre-wrap break-words font-[inherit] text-[13px] leading-relaxed"
        style={{ color }}
      >
        {line.text}
      </pre>
    </div>
  )
}

function TrafficLight({
  color,
  title,
  onClick,
}: {
  color: string
  title: string
  onClick?: () => void
}) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      onClick={(e) => {
        e.stopPropagation()
        onClick?.()
      }}
      className="size-3 rounded-full ring-1 ring-black/20 transition-transform hover:brightness-110"
      style={{ backgroundColor: color }}
    />
  )
}

function Spinner() {
  return (
    <span
      className="inline-block size-3 animate-spin rounded-full border-2 border-neutral-600 border-t-neutral-300"
      aria-hidden
    />
  )
}

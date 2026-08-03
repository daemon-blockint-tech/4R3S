import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { Components } from 'react-markdown'
import { BookText, Search } from 'lucide-react'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { PageHeader, EmptyState, ErrorState, LoadingState } from '@/components/common'

interface DocMeta {
  slug: string
  title: string
  size: number
  updatedAt: string
}

interface DocContent {
  slug: string
  title: string
  content: string
}

const mdComponents: Components = {
  h1: ({ children }) => (
    <h1 className="mb-4 mt-6 text-xl font-semibold text-foreground first:mt-0">{children}</h1>
  ),
  h2: ({ children }) => (
    <h2 className="mb-3 mt-5 text-lg font-semibold text-foreground">{children}</h2>
  ),
  h3: ({ children }) => (
    <h3 className="mb-2 mt-4 text-base font-semibold text-foreground">{children}</h3>
  ),
  h4: ({ children }) => (
    <h4 className="mb-2 mt-3 text-sm font-semibold text-foreground">{children}</h4>
  ),
  p: ({ children }) => <p className="mb-3 text-sm leading-relaxed text-muted-foreground">{children}</p>,
  ul: ({ children }) => (
    <ul className="mb-3 list-inside list-disc space-y-1 text-sm text-muted-foreground">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="mb-3 list-inside list-decimal space-y-1 text-sm text-muted-foreground">{children}</ol>
  ),
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="mb-3 border-l-2 border-border pl-3 text-sm italic text-muted-foreground">
      {children}
    </blockquote>
  ),
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-primary hover:underline">
      {children}
    </a>
  ),
  code: ({ className, children, ...props }) => {
    const isBlock = className?.includes('language-')
    if (isBlock) {
      return (
        <code className={cn('font-mono text-xs', className)} {...props}>
          {children}
        </code>
      )
    }
    return (
      <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs" {...props}>
        {children}
      </code>
    )
  },
  pre: ({ children }) => (
    <pre className="mb-3 overflow-x-auto rounded-lg border border-border bg-background/60 p-3 font-mono text-xs">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="mb-3 overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-muted/40">{children}</thead>,
  th: ({ children }) => (
    <th className="border border-border px-3 py-1.5 text-left text-xs font-medium text-foreground">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border border-border px-3 py-1.5 text-sm text-muted-foreground">{children}</td>
  ),
  hr: () => <Separator className="my-4" />,
  strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
}

export function DocsPage() {
  const [selected, setSelected] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  const list = useQuery({
    queryKey: ['docs'],
    queryFn: () => api.get<{ docs: DocMeta[] }>('/api/docs'),
  })

  const docs = list.data?.docs ?? []

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return docs
    return docs.filter((d) => d.title.toLowerCase().includes(q) || d.slug.toLowerCase().includes(q))
  }, [docs, filter])

  useEffect(() => {
    if (!selected && docs.length > 0) {
      setSelected(docs[0].slug)
    }
  }, [docs, selected])

  const doc = useQuery({
    queryKey: ['docs', selected],
    queryFn: () => api.get<DocContent>(`/api/docs/${selected}`),
    enabled: !!selected,
  })

  if (list.isLoading) return <LoadingState label="Loading docs…" />
  if (list.error) return <ErrorState error={list.error} />
  if (!docs.length) {
    return (
      <div className="mx-auto max-w-5xl">
        <PageHeader
          title="Docs"
          description="Operator manuals and reference material shipped with ARES."
        />
        <EmptyState icon={BookText} title="No docs found" hint="Add markdown files to the docs/ directory." />
      </div>
    )
  }

  const active = docs.find((d) => d.slug === selected)

  return (
    <div className="mx-auto flex h-[calc(100dvh-7rem)] max-w-6xl flex-col">
      <PageHeader
        title="Docs"
        description="Operator manuals and reference material shipped with ARES."
      />

      <div className="flex min-h-0 flex-1 gap-4">
        <aside className="flex w-56 shrink-0 flex-col sm:w-64">
          <div className="relative mb-2">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter docs…"
              className="h-8 pl-8 text-xs"
            />
          </div>
          <ScrollArea className="flex-1 rounded-lg border border-border">
            <nav className="p-1">
              {filtered.length === 0 ? (
                <p className="px-2 py-4 text-center text-xs text-muted-foreground">No matches</p>
              ) : (
                filtered.map((d) => (
                  <button
                    key={d.slug}
                    type="button"
                    onClick={() => setSelected(d.slug)}
                    className={cn(
                      'flex w-full flex-col gap-0.5 rounded-md px-2.5 py-2 text-left transition-colors',
                      selected === d.slug
                        ? 'bg-primary/10 text-foreground'
                        : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground',
                    )}
                  >
                    <span className="text-sm font-medium leading-tight">{d.title}</span>
                    <span className="font-mono text-[10px] opacity-70">{d.slug}</span>
                  </button>
                ))
              )}
            </nav>
          </ScrollArea>
        </aside>

        <div className="min-w-0 flex-1 overflow-y-auto rounded-lg border border-border bg-card/30 p-5">
          {!selected ? (
            <EmptyState icon={BookText} title="Select a doc" />
          ) : doc.isLoading ? (
            <LoadingState label="Loading doc…" />
          ) : doc.error ? (
            <ErrorState error={doc.error} />
          ) : doc.data ? (
            <article>
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold">{doc.data.title}</h3>
                <Badge variant="outline" className="font-mono text-[10px]">
                  {doc.data.slug}
                </Badge>
                {active && (
                  <span className="text-[10px] text-muted-foreground">
                    {formatBytes(active.size)} · updated {formatDate(active.updatedAt)}
                  </span>
                )}
              </div>
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                {doc.data.content}
              </ReactMarkdown>
            </article>
          ) : null}
        </div>
      </div>
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
  } catch {
    return iso
  }
}

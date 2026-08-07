'use client'

import { useState, useMemo } from 'react'
import { useTask } from '@/lib/hooks/use-task'
import { TaskDetails } from '@/components/task-details'
import { SharedHeader } from '@/components/shared-header'
import { TaskActions } from '@/components/task-actions'
import { LogsPane } from '@/components/logs-pane'
import { Button } from '@/components/ui/button'
import Link from 'next/link'
import type { Session } from '@/lib/session/types'

interface TaskPageClientProps {
  taskId: string
  user: Session['user'] | null
  authProvider: Session['authProvider'] | null
  initialStars?: number
  maxSandboxDuration?: number
}

function parseRepoFromUrl(repoUrl: string | null): { owner: string; repo: string } | null {
  if (!repoUrl) return null
  try {
    const url = new URL(repoUrl)
    const pathParts = url.pathname.split('/').filter(Boolean)
    if (pathParts.length >= 2) {
      return {
        owner: pathParts[0],
        repo: pathParts[1].replace(/\.git$/, ''),
      }
    }
    return null
  } catch {
    return null
  }
}

export function TaskPageClient({
  taskId,
  user,
  authProvider,
  initialStars = 1200,
  maxSandboxDuration = 300,
}: TaskPageClientProps) {
  const { task, isLoading, error, refetch } = useTask(taskId)
  const [logsPaneHeight, setLogsPaneHeight] = useState(40) // Default to collapsed height

  const repoInfo = useMemo(() => parseRepoFromUrl(task?.repoUrl ?? null), [task?.repoUrl])

  const headerLeftActions = repoInfo ? (
    <div className="flex items-center gap-2 min-w-0">
      <h1 className="text-lg font-semibold truncate">
        {repoInfo.owner}/{repoInfo.repo}
      </h1>
    </div>
  ) : null

  if (isLoading) {
    return (
      <div className="flex-1 bg-background">
        <div className="p-3">
          <SharedHeader initialStars={initialStars} />
        </div>
      </div>
    )
  }

  if (error || !task) {
    const isMissing = error === 'Task not found' || (!error && !task)
    return (
      <div className="flex-1 bg-background">
        <div className="p-3">
          <SharedHeader initialStars={initialStars} />
        </div>
        <div className="mx-auto p-3">
          <div className="flex items-center justify-center h-64">
            <div className="text-center space-y-3">
              {/* A failed request and a genuinely missing task need different answers:
                  one is worth retrying, the other never will be. */}
              <h2 className="text-lg font-semibold">{isMissing ? 'Task not found' : "Couldn't load this task"}</h2>
              <p className="text-muted-foreground">
                {isMissing
                  ? 'This task does not exist, or it was deleted.'
                  : 'We couldn’t reach the server. The task may still be fine.'}
              </p>
              <div className="flex items-center justify-center gap-2">
                {!isMissing && (
                  <Button variant="outline" size="sm" onClick={() => refetch()}>
                    Retry
                  </Button>
                )}
                <Button variant={isMissing ? 'default' : 'ghost'} size="sm" asChild>
                  <Link href="/tasks">Back to tasks</Link>
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 bg-background relative flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 px-3 py-2 border-b">
        <SharedHeader
          leftActions={headerLeftActions}
          initialStars={initialStars}
          extraActions={<TaskActions task={task} />}
        />
      </div>

      {/* Task details */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden" style={{ paddingBottom: `${logsPaneHeight}px` }}>
        <TaskDetails task={task} maxSandboxDuration={maxSandboxDuration} />
      </div>

      {/* Logs pane at bottom */}
      <LogsPane task={task} onHeightChange={setLogsPaneHeight} />
    </div>
  )
}

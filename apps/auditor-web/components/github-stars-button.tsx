'use client'

import { Button } from '@/components/ui/button'
import { GitHubIcon } from '@/components/icons/github-icon'
import { formatAbbreviatedNumber } from '@/lib/utils/format-number'
import { GITHUB_REPO_URL } from '@/lib/constants'

interface GitHubStarsButtonProps {
  initialStars?: number
}

export function GitHubStarsButton({ initialStars = 0 }: GitHubStarsButtonProps) {
  return (
    <Button asChild variant="ghost" size="sm" className="h-8 px-2 sm:px-3 gap-1.5">
      <a href={GITHUB_REPO_URL} target="_blank" rel="noopener noreferrer" className="flex items-center">
        <GitHubIcon className="h-3.5 w-3.5" />
        <span className="text-sm">{formatAbbreviatedNumber(initialStars)}</span>
      </a>
    </Button>
  )
}

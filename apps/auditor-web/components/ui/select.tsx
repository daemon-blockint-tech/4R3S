// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
//
// SelectContent is wrapped, not re-exported directly. Checked every real
// usage in this app (24, across 10 files) and every real usage in War
// Room (10, across 6 files) — both sets are 100% bare <SelectContent>
// with no explicit `position` prop, meaning both silently rely on
// whatever the default happens to be. This app's own previous default
// was "popper"; the shared package's is "item-aligned" (already live,
// already verified working in War Room since UI-1). Changing the shared
// default either way would silently change real, existing dropdown
// positioning behavior somewhere. This wrapper defaults to "popper" for
// this app specifically, without touching the shared package's own
// default or affecting War Room at all — an explicit position prop
// still overrides this if ever needed.
import type { ComponentProps } from 'react'
import { SelectContent as SharedSelectContent } from '@ares/ui'

function SelectContent({ position = 'popper', ...props }: ComponentProps<typeof SharedSelectContent>) {
  return <SharedSelectContent position={position} {...props} />
}

export {
  Select,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from '@ares/ui'
export { SelectContent }

// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Uses the consolidated radix-ui package matching this codebase's
// established convention. This closes a real gap found during SEC-2's
// AdmiralPage review — War Room's raw HTML checkbox there can now use
// this styled component instead.
export { Checkbox } from '@ares/ui'

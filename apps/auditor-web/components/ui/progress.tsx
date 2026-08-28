// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Verified functionally identical (already used the consolidated
// radix-ui package, unlike most of the others) except the import path
// for cn. Real usage (usage-page-client.tsx) uses the full composable
// pattern (ProgressTrack/Label/Value), all exports preserved.
export { Progress, ProgressTrack, ProgressIndicator, ProgressLabel, ProgressValue } from '@ares/ui'

// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Only consumer was sidebar.tsx, itself now a shim — safe to convert.
export { useIsMobile } from '@ares/ui'

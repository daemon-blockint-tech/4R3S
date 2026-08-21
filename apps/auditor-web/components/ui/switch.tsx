// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Uses the consolidated radix-ui package matching this codebase's
// established convention, rather than the older individual
// @radix-ui/react-switch — same underlying primitive, styling unchanged.
export { Switch } from "@ares/ui"

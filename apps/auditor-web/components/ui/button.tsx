// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Verified byte-identical to this app's previous version except the
// import path for cn — safe, no behavior or visual change.
export { Button, buttonVariants } from "@ares/ui"

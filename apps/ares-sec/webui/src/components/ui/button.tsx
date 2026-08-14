// Re-export shim - the real implementation now lives in @ares/ui (UI-1).
// Keeps every existing import in this app unchanged while packages/ui
// becomes the actual, single source of truth.
export { Button, buttonVariants } from "@ares/ui";

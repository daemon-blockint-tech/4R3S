// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Uses vaul (not radix-ui) — added as a genuinely new dependency to
// packages/ui, matching this app's existing version exactly.
export {
  Drawer,
  DrawerPortal,
  DrawerOverlay,
  DrawerTrigger,
  DrawerClose,
  DrawerContent,
  DrawerHeader,
  DrawerFooter,
  DrawerTitle,
  DrawerDescription,
} from "@ares/ui"

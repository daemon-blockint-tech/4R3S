// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Verified genuinely identical to this app's previous version — the
// only diff was import paths and a cosmetic quote-escaping style inside
// one class string, functionally and visually identical.
export {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
} from "@ares/ui"

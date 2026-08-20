// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Verified byte-identical except the import path for cn. The shared
// tooltip.tsx originally lacked "use client" (never needed it for Vite/
// War Room) — added there directly as part of this work, so this shim
// doesn't need its own copy of the directive.
export {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@ares/ui"

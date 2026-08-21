// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Uses the consolidated radix-ui package matching this codebase's
// established convention. Uses tw-animate-css's accordion keyframes —
// confirmed both this app and War Room already have the same version
// (^1.4.0) of that package installed, so this works for both.
export {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "@ares/ui"

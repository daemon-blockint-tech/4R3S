// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Uses the consolidated radix-ui package matching this codebase's
// established convention. Uses the shared buttonVariants internally,
// matching the original's dependency on Button's variants.
export {
  AlertDialog,
  AlertDialogPortal,
  AlertDialogOverlay,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
} from '@ares/ui'

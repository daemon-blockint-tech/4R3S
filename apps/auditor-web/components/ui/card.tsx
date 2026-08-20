// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// One tiny, real difference disclosed rather than silent: the shared
// CardHeader uses gap-2 versus this app's previous gap-1.5 — a barely
// perceptible spacing nuance, not a structural change. Everything else
// was pure formatting (multi-line JSX, className order), verified
// directly before treating this as safe.
export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
} from "@ares/ui"

// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Keeps every existing import in this app unchanged while packages/ui
// becomes the actual, single source of truth.
//
// Real, visible difference from the previous local version, disclosed
// rather than silent: the shared badge is rounded-full (pill-shaped) with
// a transparent border by default, versus this app's previous rounded-md
// with a visible border. Also gains two variants this app didn't have
// before (ghost, link). This is the actual point of UI-2 — adopting the
// shared system's look, not preserving the old one — but worth anyone
// reviewing this being aware every badge in this app will look visibly
// different, not just differently coded.
export { Badge, badgeVariants } from "@ares/ui"

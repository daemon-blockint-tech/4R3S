// Re-export shim — the real implementation now lives in @ares/ui (UI-2).
// Keeps every existing import in this app unchanged while packages/ui
// becomes the actual, single source of truth.
//
// Only real consumer checked directly (components/repo-page-client.tsx):
// a simple, standard usage with no orientation/variant props, relying
// only on default behavior — the shared version's genuinely newer
// features (orientation, variant) don't change anything for this
// existing usage, they're just additionally available now.
export { Tabs, TabsList, TabsTrigger, TabsContent } from '@ares/ui'

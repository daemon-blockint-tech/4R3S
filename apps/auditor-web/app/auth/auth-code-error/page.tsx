import Link from 'next/link'

export default function AuthCodeErrorPage() {
  return (
    <main className="mx-auto flex min-h-[50vh] max-w-lg flex-col items-center justify-center gap-4 px-6 text-center">
      <h1 className="text-xl font-semibold">Sign-in failed</h1>
      <p className="text-muted-foreground text-sm">
        Supabase could not complete authentication. Check redirect URLs in the Supabase dashboard and try again.
      </p>
      <Link href="/" className="text-primary text-sm underline-offset-4 hover:underline">
        Return home
      </Link>
    </main>
  )
}

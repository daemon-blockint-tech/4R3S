'use client'

import { SharedHeader } from '@/components/shared-header'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { ThemeSelector } from '@/components/theme-selector'
import { Bell, Shield, Key } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Link from 'next/link'
import type { Session } from '@/lib/session/types'

interface SettingsPageClientProps {
  user: Session['user'] | null
  initialStars?: number
}

export function SettingsPageClient({ user, initialStars }: SettingsPageClientProps) {
  return (
    <div className="flex-1 bg-background flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 p-3">
        <SharedHeader initialStars={initialStars} />
      </div>

      <div className="flex-1 overflow-auto px-4 pb-6">
        <div className="max-w-3xl mx-auto space-y-6">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Manage your workspace preferences and account options.
            </p>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Appearance</CardTitle>
              <CardDescription>Customize how ARES Auditor looks on your device.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label className="text-sm font-medium">Theme</Label>
                  <p className="text-xs text-muted-foreground">Switch between light, dark, and system themes.</p>
                </div>
                <ThemeSelector />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Bell className="h-4 w-4" />
                Notifications
              </CardTitle>
              <CardDescription>Control how you receive updates about audits and tasks.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="email-notifications" className="text-sm font-medium">
                    Email notifications
                  </Label>
                  <p className="text-xs text-muted-foreground">Receive audit completion and finding alerts.</p>
                </div>
                <Switch id="email-notifications" disabled defaultChecked={false} />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="pr-updates" className="text-sm font-medium">
                    Pull request updates
                  </Label>
                  <p className="text-xs text-muted-foreground">Notify when agent-created PRs change status.</p>
                </div>
                <Switch id="pr-updates" disabled defaultChecked={false} />
              </div>
              <p className="text-xs text-muted-foreground">
                Notification preferences will be configurable once the alerts service is connected.
              </p>
            </CardContent>
          </Card>

          {user && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Key className="h-4 w-4" />
                  API &amp; Security
                </CardTitle>
                <CardDescription>Manage credentials and connected services.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">
                  API keys and sandbox settings are available from your account menu in the header.
                </p>
                <Button variant="outline" size="sm" asChild>
                  <Link href="/usage">View plan &amp; usage</Link>
                </Button>
              </CardContent>
            </Card>
          )}

          {!user && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Account
                </CardTitle>
                <CardDescription>Sign in to access API keys, sandboxes, and workspace settings.</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Use the sign-in button in the header to connect your GitHub or Vercel account.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

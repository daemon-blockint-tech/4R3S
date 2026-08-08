import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db/client'
import { connectors } from '@/lib/db/schema'
import { decrypt } from '@/lib/crypto'
import { maskSecret, maskEnvValues } from '@/lib/utils/secret-mask'
import { getSessionFromReq } from '@/lib/session/server'
import { eq } from 'drizzle-orm'

export async function GET(req: NextRequest) {
  try {
    const session = await getSessionFromReq(req)

    if (!session?.user?.id) {
      return NextResponse.json(
        {
          success: false,
          error: 'Unauthorized',
          data: [],
        },
        { status: 401 },
      )
    }

    const userConnectors = await db.select().from(connectors).where(eq(connectors.userId, session.user.id))

    // Never return decrypted secrets to the client; expose masked placeholders
    const maskedConnectors = userConnectors.map((connector) => ({
      ...connector,
      oauthClientSecret: maskSecret(connector.oauthClientSecret),
      env: connector.env ? maskEnvValues(JSON.parse(decrypt(connector.env))) : null,
    }))

    return NextResponse.json({
      success: true,
      data: maskedConnectors,
    })
  } catch (error) {
    console.error('Error fetching connectors:', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch connectors',
        data: [],
      },
      { status: 500 },
    )
  }
}

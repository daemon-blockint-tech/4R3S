import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // @ares/ui is physically copied into node_modules (see
  // scripts/copy-ares-ui.js) as raw TypeScript source, not pre-compiled
  // JS like a normal published package. Turbopack's default node_modules
  // handling assumes pre-compiled code and skips transformation —
  // confirmed directly: build failed with "Unknown module type... Use a
  // known file extension, or register a loader for it" on
  // node_modules/@ares/ui/src/index.ts specifically. transpilePackages
  // tells Next.js to apply its normal TS/JSX transform to this package
  // instead of treating it as already-built.
  transpilePackages: ['@ares/ui'],
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'avatars.githubusercontent.com',
        port: '',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: 'github.com',
        port: '',
        pathname: '/**',
      },
    ],
  },
}

export default nextConfig

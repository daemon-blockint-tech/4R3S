'use client'

import * as React from 'react'
import { useServerInsertedHTML } from 'next/navigation'

const DEFAULT_STORAGE_KEY = 'theme'

type ThemeSetting = 'light' | 'dark' | 'system'
type ResolvedTheme = 'light' | 'dark'

export interface ThemeProviderProps {
  children: React.ReactNode
  attribute?: 'class' | `data-${string}`
  defaultTheme?: ThemeSetting
  enableSystem?: boolean
  disableTransitionOnChange?: boolean
  storageKey?: string
  forcedTheme?: ThemeSetting
  themes?: ThemeSetting[]
}

interface ThemeContextValue {
  theme?: string
  setTheme: React.Dispatch<React.SetStateAction<string>>
  forcedTheme?: string
  resolvedTheme?: ResolvedTheme
  systemTheme?: ResolvedTheme
  themes: string[]
}

const ThemeContext = React.createContext<ThemeContextValue>({
  setTheme: () => {},
  themes: ['light', 'dark', 'system'],
})

function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined') {
    return 'light'
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function buildThemeInitScript(storageKey: string, defaultTheme: ThemeSetting, enableSystem: boolean) {
  const defaultValue = enableSystem ? defaultTheme : defaultTheme === 'system' ? 'light' : defaultTheme
  return `(function(){try{var d=document.documentElement;var k=${JSON.stringify(storageKey)};var t=localStorage.getItem(k)||${JSON.stringify(defaultValue)};var s=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';var r=t==='system'&&${enableSystem ? 'true' : 'false'}?s:t;if(r==='dark'){d.classList.add('dark');d.style.colorScheme='dark'}else{d.classList.remove('dark');d.style.colorScheme='light'}}catch(e){}})();`
}

function ThemeInitScript({
  storageKey,
  defaultTheme,
  enableSystem,
}: {
  storageKey: string
  defaultTheme: ThemeSetting
  enableSystem: boolean
}) {
  useServerInsertedHTML(() => (
    <script
      dangerouslySetInnerHTML={{ __html: buildThemeInitScript(storageKey, defaultTheme, enableSystem) }}
      suppressHydrationWarning
    />
  ))
  return null
}

function disableTransitions(nonce?: string) {
  const css = document.createElement('style')
  if (nonce) {
    css.setAttribute('nonce', nonce)
  }
  css.appendChild(
    document.createTextNode(
      '*,*::before,*::after{-webkit-transition:none!important;-moz-transition:none!important;-o-transition:none!important;transition:none!important}',
    ),
  )
  document.head.appendChild(css)
  return () => {
    window.getComputedStyle(document.body)
    setTimeout(() => {
      document.head.removeChild(css)
    }, 1)
  }
}

function applyThemeToDocument(theme: ResolvedTheme, attribute: ThemeProviderProps['attribute']) {
  const root = document.documentElement
  if (attribute === 'class') {
    root.classList.toggle('dark', theme === 'dark')
  } else if (attribute?.startsWith('data-')) {
    root.setAttribute(attribute, theme)
  }
  root.style.colorScheme = theme
}

export function ThemeProvider({
  children,
  attribute = 'class',
  defaultTheme = 'system',
  enableSystem = true,
  disableTransitionOnChange = false,
  storageKey = DEFAULT_STORAGE_KEY,
  forcedTheme,
  themes = ['light', 'dark', 'system'],
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<ThemeSetting>(() => {
    if (typeof window === 'undefined') {
      return defaultTheme
    }
    try {
      return (localStorage.getItem(storageKey) as ThemeSetting | null) ?? defaultTheme
    } catch {
      return defaultTheme
    }
  })
  const [systemTheme, setSystemTheme] = React.useState<ResolvedTheme>(() => getSystemTheme())

  const activeTheme = (forcedTheme ?? theme) as ThemeSetting
  const resolvedTheme: ResolvedTheme =
    activeTheme === 'system' && enableSystem ? systemTheme : activeTheme === 'dark' ? 'dark' : 'light'

  const setTheme = React.useCallback(
    (value: React.SetStateAction<string>) => {
      setThemeState((prev) => {
        const next = typeof value === 'function' ? (value(prev) as ThemeSetting) : (value as ThemeSetting)
        try {
          localStorage.setItem(storageKey, next)
        } catch {
          // ignore storage failures (private mode)
        }
        return next
      })
    },
    [storageKey],
  )

  React.useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setSystemTheme(media.matches ? 'dark' : 'light')
    onChange()
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  React.useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== storageKey) return
      setThemeState((event.newValue as ThemeSetting | null) ?? defaultTheme)
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [defaultTheme, storageKey])

  React.useEffect(() => {
    const restoreTransitions = disableTransitionOnChange ? disableTransitions() : undefined
    applyThemeToDocument(resolvedTheme, attribute)
    restoreTransitions?.()
  }, [attribute, disableTransitionOnChange, resolvedTheme])

  const value = React.useMemo<ThemeContextValue>(
    () => ({
      theme: activeTheme,
      setTheme,
      forcedTheme,
      resolvedTheme,
      systemTheme: enableSystem ? systemTheme : undefined,
      themes: enableSystem ? themes.map(String) : themes.filter((t) => t !== 'system').map(String),
    }),
    [activeTheme, enableSystem, forcedTheme, resolvedTheme, setTheme, systemTheme, themes],
  )

  return (
    <ThemeContext.Provider value={value}>
      <ThemeInitScript storageKey={storageKey} defaultTheme={defaultTheme} enableSystem={enableSystem} />
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return React.useContext(ThemeContext)
}

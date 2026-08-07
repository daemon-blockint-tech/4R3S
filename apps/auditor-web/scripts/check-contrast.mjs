// Guards the focus-ring contrast floor. Run: node scripts/check-contrast.mjs
// Reads the live --ring / --background tokens out of app/globals.css so the check
// fails if someone lowers them again. Achromatic oklch only (a=b=0), which is all
// these tokens use.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const css = readFileSync(new URL('../app/globals.css', import.meta.url), 'utf8')

// oklch(L 0 0): l=m=s=L^3, so every linear-sRGB channel is L^3.
const luminance = (L) => L ** 3
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

/** Pull the Nth occurrence of a token, in source order (1st = light block, 2nd = dark). */
function token(name, occurrence) {
  const hits = [...css.matchAll(new RegExp(`--${name}:\\s*oklch\\(([0-9.]+)\\s+0\\s+0\\)`, 'g'))]
  assert.ok(hits[occurrence], `--${name} occurrence ${occurrence} not found or not achromatic oklch`)
  return Number(hits[occurrence][1])
}

const MIN = 3 // WCAG 1.4.11 non-text contrast, applies to focus indicators
const themes = [
  { name: 'light', ring: token('ring', 0), bg: token('background', 0) },
  { name: 'dark', ring: token('ring', 1), bg: token('background', 1) },
]

for (const { name, ring, bg } of themes) {
  const ratio = contrast(ring, bg)
  console.log(`${name}: --ring ${ring} on --background ${bg} = ${ratio.toFixed(2)}:1`)
  assert.ok(ratio >= MIN, `${name} focus ring is ${ratio.toFixed(2)}:1, below the ${MIN}:1 minimum`)
}

console.log('ok: focus ring clears 3:1 in both themes')

// ponytail: achromatic-only math; if a chromatic --ring is ever introduced this needs
// a real oklch->sRGB conversion (culori) rather than the L^3 shortcut.

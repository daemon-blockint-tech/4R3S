#!/usr/bin/env node
// Copies packages/ui into node_modules/@ares/ui as real, physical files —
// not a symlink. After repeated Turbopack-on-Windows failures resolving
// @ares/ui via both externalDir+symlink and resolveAlias (an absolute
// path hit an unimplemented "windows imports" code path; a relative path
// then resolved against each importing file's own location rather than
// a fixed root, given every file failed identically regardless of
// nesting depth), this sidesteps the whole class of problem: a real,
// ordinary node_modules package needs no special resolution handling at
// all — every bundler is built to handle this correctly by default.
//
// Trade-off, accepted deliberately: this is a copy, not a live link.
// Changes to packages/ui's source won't appear in auditor-web until this
// script re-runs — wired as postinstall so `npm install` always refreshes
// it automatically.

const fs = require('fs')
const path = require('path')

const SRC = path.join(__dirname, '..', '..', '..', 'packages', 'ui')
const DEST = path.join(__dirname, '..', 'node_modules', '@ares', 'ui')

function copyRecursive(src, dest) {
  const stat = fs.statSync(src)
  if (stat.isDirectory()) {
    if (path.basename(src) === 'node_modules') return
    fs.mkdirSync(dest, { recursive: true })
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry))
    }
  } else {
    fs.mkdirSync(path.dirname(dest), { recursive: true })
    fs.copyFileSync(src, dest)
  }
}

if (!fs.existsSync(SRC)) {
  console.error(`copy-ares-ui: source not found at ${SRC}`)
  process.exit(1)
}

fs.rmSync(DEST, { recursive: true, force: true })
copyRecursive(path.join(SRC, 'package.json'), path.join(DEST, 'package.json'))
copyRecursive(path.join(SRC, 'src'), path.join(DEST, 'src'))

console.log(`copy-ares-ui: copied packages/ui -> ${DEST}`)

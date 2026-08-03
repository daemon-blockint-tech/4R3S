#!/bin/sh
# install-hooks.sh — activate the ares push guard.
#
# Sets core.hooksPath to .githooks AND copies the pre-push hook into
# .git/hooks/pre-push so the guard fires even if hooksPath is ignored
# (e.g. older git, or an override elsewhere). Run from the repo root.

set -e

# Resolve the repo root regardless of where this script is invoked from.
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# 1) Point git at the tracked .githooks directory.
git config core.hooksPath .githooks

# 2) Belt-and-suspenders: also install directly into .git/hooks.
mkdir -p .git/hooks
cp .githooks/pre-push .git/hooks/pre-push

# 3) Make both executable.
chmod +x .githooks/pre-push .git/hooks/pre-push

echo "ares push guard installed: core.hooksPath=.githooks + .git/hooks/pre-push (both executable)."

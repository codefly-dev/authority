#!/bin/sh
# Run after npm ci. Codefly embeds this committed browser bundle in the edge.
set -eu
cd "$(dirname "$0")/.."
npm run build
git diff --exit-code -- ../code/signin/out
if [ -n "$(git ls-files --others --exclude-standard -- ../code/signin/out)" ]; then
  echo 'sign-in bundle drift: the rebuild created uncommitted assets' >&2
  exit 1
fi

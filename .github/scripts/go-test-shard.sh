#!/usr/bin/env bash
# go-test-shard.sh <i> <n> — one of n disjoint parts of a module's race tests,
# for go.yml's modules whose tests outlast every other job in the run.
#
# Run from the module's root. It lists every top-level test, example and fuzz
# target the module declares (`go test -list`, so the list is what the compiler
# sees, build tags included), sorts the distinct names, and runs those at
# positions i, i+n, i+2n, … with the flags the unsplit job uses:
# `go test -race -count=1 ./...`. Every shard computes the same list from the
# same commit, so the n shards together run each test exactly once and nothing
# else. A name two packages share runs in both, in the one shard that holds it.
#
# A shard that would run nothing fails: a split that silently drops tests is
# the failure this script exists to rule out.
set -euo pipefail

i=${1:?usage: go-test-shard.sh <i> <n>}
n=${2:?usage: go-test-shard.sh <i> <n>}
if ! [[ "$i" =~ ^[1-9][0-9]*$ && "$n" =~ ^[1-9][0-9]*$ ]] || [ "$i" -gt "$n" ]; then
  echo "go-test-shard: need 1 <= i <= n, got <$i>/<$n>" >&2
  exit 2
fi

# A failing list (a package that does not compile) fails the script here.
listing=$(go test -list '.*' ./...)
names=$(printf '%s\n' "$listing" | grep -E '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' | LC_ALL=C sort -u || true)
total=$(printf '%s' "$names" | grep -c . || true)
if [ "$total" -eq 0 ]; then
  echo "go-test-shard: the module lists no test" >&2
  exit 2
fi

selected=$(printf '%s\n' "$names" | awk -v i="$i" -v n="$n" '(NR - 1) % n == i - 1')
count=$(printf '%s' "$selected" | grep -c . || true)
if [ "$count" -eq 0 ]; then
  echo "go-test-shard: shard $i/$n selects none of the module's $total tests" >&2
  exit 2
fi
echo "go-test-shard: shard $i/$n runs $count of $total top-level tests"

pattern="^($(printf '%s\n' "$selected" | paste -sd '|' -))\$"
exec go test -race -count=1 -run "$pattern" ./...

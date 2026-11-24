#!/usr/bin/env bash
# go-test-shard.sh <i> <n> — one of n disjoint parts of a module's race tests,
# for go.yml's modules whose tests outlast every other job in the run.
#
# Run from the module's root. It lists every top-level test, example and fuzz
# target the module declares (`go test -list`, so the list is what the compiler
# sees, build tags included) and runs the distinct names whose checksum
# (cksum, modulo n) is i - 1, with the flags the unsplit job uses:
# `go test -race -count=1 ./...`. A name's shard depends on the name alone,
# so the n shards together run each test exactly once and nothing else. A name
# two packages share runs in both, in the one shard that holds it.
#
# By checksum, not by position in the sorted list: tests are named in
# families (the same case for each of three kinds, say), and every n-th name
# of a sorted list then picks the same member of each family. Measured on
# libraries/authority-core/go, a split by position put 166 s of 207 s in one
# shard of three.
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

selected=$(printf '%s\n' "$names" | while IFS= read -r name; do
  sum=$(printf '%s' "$name" | cksum)
  if [ $((${sum%% *} % n)) -eq $((i - 1)) ]; then printf '%s\n' "$name"; fi
done)
count=$(printf '%s' "$selected" | grep -c . || true)
if [ "$count" -eq 0 ]; then
  echo "go-test-shard: shard $i/$n selects none of the module's $total tests" >&2
  exit 2
fi
echo "go-test-shard: shard $i/$n runs $count of $total top-level tests"

pattern="^($(printf '%s\n' "$selected" | paste -sd '|' -))\$"
exec go test -race -count=1 -run "$pattern" ./...

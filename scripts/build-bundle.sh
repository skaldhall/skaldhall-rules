#!/bin/bash
# Pack rules/<category>/*.yml into rules.tgz at the repo root.
# The operator fetches this bundle and uploads each rule via the
# OpenSearch Security Analytics custom-rules API.
set -e
cd "$(dirname "$0")/.."

[ -d rules ] || { echo "no rules/ dir"; exit 1; }

# Count rules first so we have a deterministic message even when find
# matches nothing in some categories.
n=$(find rules -type f -name '*.yml' | wc -l)
if [ "$n" -eq 0 ]; then
  echo "no rules to bundle"
  exit 1
fi

tar -czf rules.tgz rules
echo "wrote rules.tgz ($n rules)"

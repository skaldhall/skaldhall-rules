#!/bin/bash
# Validate every rule:
#   - parses as YAML
#   - has required Sigma keys (title, id, status, description, logsource, detection, level)
#   - id is a UUID-ish slug, unique across the repo
#   - file lives under rules/<known-category>/
cd "$(dirname "$0")/.."

KNOWN_CATEGORIES=(linux network others_web dns cloudtrail \
  bragi-process bragi-network bragi-finding bragi-vuln bragi-compliance \
  bragi-iam bragi-lifecycle bragi-datastore bragi-remediation bragi-policy)

is_known_cat() {
  for c in "${KNOWN_CATEGORIES[@]}"; do
    [ "$c" = "$1" ] && return 0
  done
  return 1
}

FAIL=0
COUNT=0
declare -A SEEN_IDS

for f in $(find rules -type f -name '*.yml' | sort); do
  COUNT=$((COUNT+1))
  cat="$(basename "$(dirname "$f")")"
  if ! is_known_cat "$cat"; then
    echo "FAIL: $f — unknown category '$cat' (add it to scripts/validate.sh::KNOWN_CATEGORIES)"
    FAIL=$((FAIL+1))
    continue
  fi
  # Validate via python (yaml is in stdlib via pyyaml — fall back to a bash-only check if missing).
  err=$(python3 - "$f" <<'PY'
import sys, re
try:
    import yaml
except ImportError:
    print("PyYAML not installed — skipping deep validation")
    sys.exit(0)
path = sys.argv[1]
with open(path) as f:
    try:
        d = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"invalid YAML: {e}")
        sys.exit(1)
if not isinstance(d, dict):
    print("rule must be a mapping at the top level")
    sys.exit(1)
required = ["title","id","status","description","logsource","detection","level"]
missing = [k for k in required if k not in d]
if missing:
    print(f"missing keys: {missing}")
    sys.exit(1)
rid = str(d["id"])
if not re.match(r"^[A-Za-z0-9._\-]{6,}$", rid):
    print(f"id must be 6+ chars of [A-Za-z0-9._-]: {rid!r}")
    sys.exit(1)
print(f"OK::{rid}")
PY
  ) || { echo "FAIL: $f — $err"; FAIL=$((FAIL+1)); continue; }
  rid="${err##*::}"
  if [ -z "$rid" ] || [ "$rid" = "$err" ]; then
    # python branch printed something other than OK::<id>
    echo "FAIL: $f — $err"
    FAIL=$((FAIL+1))
    continue
  fi
  if [ -n "${SEEN_IDS[$rid]:-}" ]; then
    echo "FAIL: $f — duplicate id $rid (also in ${SEEN_IDS[$rid]})"
    FAIL=$((FAIL+1))
    continue
  fi
  SEEN_IDS[$rid]="$f"
done

if [ $FAIL -gt 0 ]; then
  echo "$FAIL rule(s) failed validation (out of $COUNT)"
  exit 1
fi
echo "OK: $COUNT rules validate"

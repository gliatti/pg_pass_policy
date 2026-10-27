#!/usr/bin/env bash
# run-all.sh — construit et teste pg_pass_policy sur PostgreSQL 14 → 18.
#
# Usage : docker/run-all.sh [-j] [version…]
#   -j        exécution en parallèle (une version par processus, journaux séparés)
#   version   sous-ensemble, ex. : docker/run-all.sh 16 18
# Journaux : docker/logs/pgNN.log. Code retour non nul si une version échoue.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
compose=(docker compose -f "$here/compose.yml")
parallel=0
if [ "${1:-}" = "-j" ]; then
	parallel=1
	shift
fi
versions=("$@")
[ ${#versions[@]} -gt 0 ] || versions=(14 15 16 17 18)

logdir="$here/logs"
mkdir -p "$logdir"

run_one() {
	local v=$1 log="$logdir/pg$1.log"
	{
		echo "### build pg$v"
		"${compose[@]}" build "pg$v" &&
			echo "### test pg$v" &&
			"${compose[@]}" run --rm "pg$v"
	} >"$log" 2>&1
}

declare -A status
if [ "$parallel" -eq 1 ]; then
	declare -A pids
	for v in "${versions[@]}"; do
		run_one "$v" &
		pids[$v]=$!
	done
	for v in "${versions[@]}"; do
		if wait "${pids[$v]}"; then status[$v]=PASS; else status[$v]=FAIL; fi
	done
else
	for v in "${versions[@]}"; do
		echo "=== PostgreSQL $v (journal : $logdir/pg$v.log) ==="
		if run_one "$v"; then status[$v]=PASS; else status[$v]=FAIL; fi
		echo "    ${status[$v]}"
	done
fi

echo
echo "=== récapitulatif ==="
failed=0
for v in "${versions[@]}"; do
	printf '  PostgreSQL %-3s %s\n' "$v" "${status[$v]}"
	if [ "${status[$v]}" != PASS ]; then
		failed=$((failed + 1))
		grep -E 'not ok|FAIL|failed|ERROR' "$logdir/pg$v.log" | head -n 15 | sed 's/^/      | /' || true
	fi
done
if [ "$failed" -ne 0 ]; then
	echo "$failed version(s) en échec"
	exit 1
fi
echo "toutes les versions sont passées"

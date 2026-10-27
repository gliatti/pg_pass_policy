#!/usr/bin/env bash
# run-all.sh — exécute tous les tests shell (une instance temporaire par script)
# et affiche un récapitulatif. Code retour non nul si au moins un script échoue.
#
# Usage : test/shell/run-all.sh [script…]   (défaut : tous les *.sh du répertoire)
# Pré-requis : make install déjà fait pour le PG_CONFIG utilisé.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
export PG_CONFIG=${PG_CONFIG:-pg_config}

if [ $# -gt 0 ]; then
	scripts=("$@")
else
	scripts=()
	for f in "$here"/*.sh; do
		case "$(basename "$f")" in
		common.sh | run-all.sh) ;;
		*) scripts+=("$f") ;;
		esac
	done
fi

declare -a names results
failed=0
for s in "${scripts[@]}"; do
	name=$(basename "$s" .sh)
	echo "=== $name ==="
	start=$SECONDS
	if bash "$s"; then
		res=PASS
	else
		res=FAIL
		failed=$((failed + 1))
	fi
	names+=("$name")
	results+=("$res ($((SECONDS - start)) s)")
	echo
done

echo "=== récapitulatif des tests shell ($("$PG_CONFIG" --version)) ==="
for i in "${!names[@]}"; do
	printf '  %-12s %s\n' "${names[$i]}" "${results[$i]}"
done
if [ "$failed" -ne 0 ]; then
	echo "$failed script(s) en échec"
	exit 1
fi
echo "tous les scripts sont passés"

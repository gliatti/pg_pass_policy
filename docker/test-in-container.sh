#!/usr/bin/env bash
# test-in-container.sh — lancé dans le conteneur (utilisateur postgres) :
# tests pg_regress sur instance temporaire, puis tests shell.
set -euo pipefail
cd /src

echo "=== $(pg_config --version) : pg_regress ==="
rc=0
# PGXS ne prend pas en charge « make check » : installcheck + --temp-instance
# crée une instance dédiée chargeant test/pg_pass_policy.conf. TEMP_INSTANCE
# (variable du Makefile) place cette instance dans le tmpfs /tmp : la couche
# overlay du conteneur peut être exiguë (« No space left on device » à l'initdb).
if ! make installcheck TEMP_INSTANCE=/tmp/ppp_regress; then
	rc=1
	echo "=== test/regression.diffs ==="
	cat test/regression.diffs 2>/dev/null || true
fi

echo "=== $(pg_config --version) : tests shell ==="
if ! test/shell/run-all.sh; then
	rc=1
fi
exit "$rc"

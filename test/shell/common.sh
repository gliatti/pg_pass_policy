#!/usr/bin/env bash
# common.sh — fonctions partagées des tests shell de pg_pass_policy.
#
# À sourcer depuis un script en mode strict (set -euo pipefail). Fournit :
#   ppp_start [clé=valeur …]   initdb + démarrage d'une instance temporaire
#                              (port libre, 127.0.0.1 uniquement, pas de socket
#                              Unix), conf = test/pg_pass_policy.conf + surcharges
#   ppp_stop                   arrêt (appelé automatiquement par trap EXIT)
#   psql_admin SQL             exécute SQL en superutilisateur (trust), sortie -At
#   psql_as ROLE PWD SQL       connexion réelle en SCRAM avec PGPASSWORD=PWD ;
#                              stdout+stderr sur la sortie, code retour de psql
#   wait_for SECS SQL          attend que SQL renvoie 't' (sondage toutes les 0,5 s)
#   ok / fail / check_eq / check_contains / check_not_contains / ppp_finish
#
# Variables : PG_CONFIG (défaut pg_config), PPP_KEEP_TMP=1 pour conserver le
# répertoire temporaire (données + log) après exécution, PPP_LOCALE (défaut C)
# pour la locale de l'initdb (unicode.sh utilise C.UTF-8).
#
# L'extension doit avoir été installée au préalable (make install).

PG_CONFIG=${PG_CONFIG:-pg_config}
PPP_BINDIR=$("$PG_CONFIG" --bindir)
PPP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PPP_SUPERUSER=ppp_test_super
PPP_LOCALE=${PPP_LOCALE:-C}
PPP_DB=postgres
PPP_TMP=""
PPP_PORT=""
PPP_PASS=0
PPP_FAIL=0
PPP_TEST_NAME=$(basename "$0" .sh)

export PGCONNECT_TIMEOUT=10
# Ne jamais hériter d'une configuration libpq de l'appelant
unset PGSERVICE PGSERVICEFILE PGPASSFILE PGOPTIONS PGSSLMODE PGDATABASE PGUSER PGHOST PGPORT PGPASSWORD || true

log() { printf '[%s] %s\n' "$PPP_TEST_NAME" "$*"; }

ok() {
	PPP_PASS=$((PPP_PASS + 1))
	printf '[%s]   ok   - %s\n' "$PPP_TEST_NAME" "$1"
}

fail() {
	PPP_FAIL=$((PPP_FAIL + 1))
	printf '[%s]   FAIL - %s\n' "$PPP_TEST_NAME" "$1"
	if [ $# -ge 2 ]; then
		printf '%s\n' "$2" | sed 's/^/        | /'
	fi
}

# check_eq DESCRIPTION ATTENDU OBTENU
check_eq() {
	if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "attendu: [$2]"$'\n'"obtenu : [$3]"; fi
}

# check_contains DESCRIPTION MOTIF(regex grep -E, insensible à la casse) TEXTE
check_contains() {
	if printf '%s' "$3" | grep -qiE -- "$2"; then ok "$1"; else fail "$1" "motif absent: $2"$'\n'"$3"; fi
}

check_not_contains() {
	if printf '%s' "$3" | grep -qiE -- "$2"; then fail "$1" "motif présent: $2"$'\n'"$3"; else ok "$1"; fi
}

# Port TCP libre sur 127.0.0.1 (test par connexion /dev/tcp)
ppp_free_port() {
	local port=$((54400 + RANDOM % 500))
	for _ in $(seq 1 200); do
		if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
			echo "$port"
			return 0
		fi
		port=$((port + 1))
	done
	echo "aucun port libre trouvé" >&2
	return 1
}

ppp_stop() {
	local rc=${1:-$?}
	if [ -n "$PPP_TMP" ] && [ -d "$PPP_TMP/data" ]; then
		"$PPP_BINDIR/pg_ctl" -D "$PPP_TMP/data" -m immediate -w stop >/dev/null 2>&1 || true
		if [ "$rc" -ne 0 ] || [ "$PPP_FAIL" -ne 0 ]; then
			log "fin du log serveur ($PPP_TMP/server.log) :"
			tail -n 40 "$PPP_TMP/server.log" 2>/dev/null | sed 's/^/        | /' || true
		fi
		if [ "${PPP_KEEP_TMP:-0}" = 1 ]; then
			log "répertoire conservé : $PPP_TMP"
		else
			rm -rf "$PPP_TMP"
		fi
	fi
	PPP_TMP=""
	return "$rc"
}

trap ppp_stop EXIT
trap 'exit 130' INT TERM

# ppp_start [paramètre=valeur …] : surcharges ajoutées en fin de postgresql.conf
ppp_start() {
	PPP_TMP=$(mktemp -d "${TMPDIR:-/tmp}/ppp_test.XXXXXX")

	"$PPP_BINDIR/initdb" -D "$PPP_TMP/data" -U "$PPP_SUPERUSER" -A trust \
		--no-sync -E UTF8 --locale="$PPP_LOCALE" >"$PPP_TMP/initdb.log" 2>&1 || {
		cat "$PPP_TMP/initdb.log"
		return 1
	}

	{
		cat "$PPP_ROOT/test/pg_pass_policy.conf"
		echo
		echo "# --- surcharges test/shell/common.sh ---"
		echo "listen_addresses = '127.0.0.1'"
		echo "# port : passé par pg_ctl -o '-p N' (nouveau tirage si le port est pris)"
		echo "unix_socket_directories = ''"
		echo "pg_pass_policy.database = '$PPP_DB'"
		echo "pg_pass_policy.worker_interval = 2"
		echo "log_connections = on"
		echo "log_line_prefix = '%m [%p] %q%u@%d '"
		echo "fsync = off"
		local kv
		for kv in "$@"; do
			echo "$kv"
		done
	} >>"$PPP_TMP/data/postgresql.conf"

	# Superutilisateur de test en trust, tous les autres rôles en SCRAM
	cat >"$PPP_TMP/data/pg_hba.conf" <<-HBA
		host all $PPP_SUPERUSER 127.0.0.1/32 trust
		host all all            127.0.0.1/32 scram-sha-256
	HBA

	# La plage 54400-54899 est dans la plage éphémère de Linux : un port libre
	# à l'écoute peut être occupé côté client (psql d'un test précédent) et le
	# bind() échouer. On retire alors un autre port, au plus 5 fois.
	local attempt
	for attempt in 1 2 3 4 5; do
		PPP_PORT=$(ppp_free_port)
		rm -f "$PPP_TMP/server.log"
		if "$PPP_BINDIR/pg_ctl" -D "$PPP_TMP/data" -l "$PPP_TMP/server.log" \
			-o "-p $PPP_PORT" -w -t 60 start >/dev/null 2>&1; then
			break
		fi
		if grep -q 'Address already in use' "$PPP_TMP/server.log" 2>/dev/null &&
			[ "$attempt" -lt 5 ]; then
			log "port $PPP_PORT déjà pris, nouveau tirage ($attempt/5)"
			continue
		fi
		tail -n 30 "$PPP_TMP/server.log"
		return 1
	done
	log "instance temporaire : $PPP_TMP (port $PPP_PORT, $("$PPP_BINDIR/postgres" --version))"
	psql_admin "CREATE EXTENSION pg_pass_policy" >/dev/null
}

psql_admin() {
	"$PPP_BINDIR/psql" -X -q -At -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$PPP_PORT" -U "$PPP_SUPERUSER" -d "$PPP_DB" -c "$1"
}

# psql_admin_script : comme psql_admin, mais lit un script SQL sur l'entrée
# standard (transactions explicites, SAVEPOINT…) ; stdout+stderr sur la sortie
psql_admin_script() {
	"$PPP_BINDIR/psql" -X -q -At -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$PPP_PORT" -U "$PPP_SUPERUSER" -d "$PPP_DB" 2>&1
}

# psql_as ROLE PASSWORD [SQL] : vraie authentification SCRAM sur 127.0.0.1.
# Le mot de passe passe par l'environnement, jamais sur la ligne de commande.
psql_as() {
	local role=$1 pwd=$2 sql=${3:-SELECT 1}
	PGPASSWORD=$pwd "$PPP_BINDIR/psql" -X -q -At -w -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$PPP_PORT" -U "$role" -d "$PPP_DB" -c "$sql" 2>&1
}

# wait_for TIMEOUT_SECONDES SQL : attend que SQL (exécuté en admin) renvoie 't'
wait_for() {
	local timeout=$1 sql=$2 deadline
	deadline=$((SECONDS + timeout))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if [ "$(psql_admin "$sql" 2>/dev/null || true)" = "t" ]; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

# Attend un tour complet du worker postérieur à l'appel
wait_worker_run() {
	local timeout=${1:-30} t0
	t0=$(psql_admin "SELECT clock_timestamp()")
	wait_for "$timeout" "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()"
}

ppp_finish() {
	log "résultat : $PPP_PASS ok, $PPP_FAIL échec(s)"
	[ "$PPP_FAIL" -eq 0 ]
}

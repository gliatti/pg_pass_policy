#!/usr/bin/env bash
# notify.sh — NOTIFY émis par audit() (SPEC §4 audit(), message JSON
# {"event","role","at","details"}) et absence de mot de passe dans la charge utile.
#
# 1. même session : LISTEN puis rotate_password (une session reçoit ses propres
#    notifications après COMMIT) — déterministe ;
# 2. deux sessions : un écouteur en pg_sleep, rotation depuis une autre session ;
#    la notification est délivrée quand l'écouteur redevient inactif ;
# 3. canal personnalisé via pg_pass_policy.notify_channel ;
# 4. refus PPP-xxx par le hook : le mot de passe refusé n'apparaît ni dans le
#    log serveur (STATEMENT, CONTEXT) ni dans l'audit.
set -euo pipefail
. "$(dirname "$0")/common.sh"

LISTENER_PID=""
cleanup_listener() {
	if [ -n "$LISTENER_PID" ]; then
		kill "$LISTENER_PID" 2>/dev/null || true
		wait "$LISTENER_PID" 2>/dev/null || true
	fi
}
trap 'rc=$?; cleanup_listener; ppp_stop "$rc"' EXIT

# psql admin lisant ses commandes sur l'entrée standard (une requête par ligne)
psql_admin_stdin() {
	"$PPP_BINDIR/psql" -X -At -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$PPP_PORT" -U "$PPP_SUPERUSER" -d "$PPP_DB" 2>&1
}

# shellcheck disable=SC2119 # pas de surcharge de configuration
ppp_start

psql_admin "CREATE ROLE regress_notify LOGIN"
psql_admin "SELECT pass_policy.create_profile('p_notify', '{\"min_age\": \"0\"}')" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_notify', 'p_notify')" >/dev/null

# --- 1. même session -------------------------------------------------------------
out=$(printf '%s\n' \
	"LISTEN pg_pass_policy;" \
	"CREATE TEMP TABLE s AS SELECT pass_policy.rotate_password('regress_notify') AS p;" \
	"SELECT 'PWD=' || p FROM s;" \
	"SELECT 'done';" | psql_admin_stdin)
pwd=$(printf '%s\n' "$out" | sed -n 's/^PWD=//p')
notif=$(printf '%s\n' "$out" | grep 'Asynchronous notification "pg_pass_policy"' || true)
check_contains "notification reçue (même session)" 'Asynchronous notification "pg_pass_policy"' "$notif"
check_contains "charge utile : event = password_rotated" '"event" ?: ?"password_rotated"' "$notif"
check_contains "charge utile : role = regress_notify" '"role" ?: ?"regress_notify"' "$notif"
check_contains "charge utile : champ at" '"at" ?:' "$notif"
if [ -n "$pwd" ] && ! printf '%s' "$notif" | grep -qF -- "$pwd"; then
	ok "le mot de passe n'est pas dans la notification"
else
	fail "mot de passe absent du résultat ou présent dans la notification"
fi
check_not_contains "pas de vérificateur dans la notification" 'SCRAM-SHA-256\$' "$notif"
if [ -n "$pwd" ] && grep -qF -- "$pwd" "$PPP_TMP/server.log"; then
	fail "le mot de passe généré apparaît dans le log serveur (SPEC §8.1)"
else
	ok "le mot de passe généré n'est pas dans le log serveur"
fi

# --- 2. deux sessions --------------------------------------------------------------
listen_out="$PPP_TMP/listener.out"
printf '%s\n' "LISTEN pg_pass_policy;" "SELECT pg_sleep(4);" "SELECT 'listener done';" \
	| psql_admin_stdin >"$listen_out" &
LISTENER_PID=$!
sleep 1.5
psql_admin "SELECT pass_policy.lock_role('regress_notify', interval '1 minute', 'notify test')" >/dev/null
wait "$LISTENER_PID" || true
LISTENER_PID=""
notif=$(grep 'Asynchronous notification "pg_pass_policy"' "$listen_out" || true)
check_contains "notification reçue par une autre session" '"event" ?: ?"role_locked"' "$notif"
psql_admin "SELECT pass_policy.unlock_role('regress_notify')" >/dev/null

# --- 3. canal personnalisé ------------------------------------------------------------
psql_admin "ALTER SYSTEM SET pg_pass_policy.notify_channel = 'ppp_custom'"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
out=$(printf '%s\n' \
	"SHOW pg_pass_policy.notify_channel;" \
	"LISTEN ppp_custom;" \
	"LISTEN pg_pass_policy;" \
	"SELECT pass_policy.audit('maintenance', 'regress_notify', '{\"source\": \"notify.sh\"}');" \
	"SELECT 'done';" | psql_admin_stdin)
check_contains "notification sur le canal personnalisé" 'Asynchronous notification "ppp_custom"' "$out"
check_not_contains "plus rien sur l'ancien canal" 'Asynchronous notification "pg_pass_policy"' "$out"
check_contains "details transmis" '"source" ?: ?"notify.sh"' "$out"

# --- 4. refus du hook : rien dans le log serveur (SPEC §8.1) ---------------------------
# Une ERROR est écrite dans le log au moment où elle est levée, même si un bloc
# EXCEPTION la rattrape ensuite : ni la ligne STATEMENT ni la ligne CONTEXT
# (« SQL statement "ALTER ROLE … PASSWORD '…'" » quand l'ALTER ROLE passe par
# EXECUTE) ne doivent contenir le mot de passe. Trois chemins, un mot de passe
# unique (trop court : PPP-010) par chemin, pour savoir lequel fuit.
# superuser_bypass est à off par défaut : le superutilisateur est refusé aussi.
leak_probe() {
	local desc=$1 probe=$2 sql=$3 out n
	out=$(psql_admin "$sql" 2>&1) || true
	check_contains "$desc : refus PPP-010" 'PPP-010' "$out"
	sleep 0.5
	n=$(grep -cF -- "$probe" "$PPP_TMP/server.log" || true)
	check_eq "$desc : mot de passe absent du log serveur" "0" "$n"
}
leak_probe "ALTER ROLE direct" 'leakprobe1' \
	"ALTER ROLE regress_notify PASSWORD 'leakprobe1'"
leak_probe "ALTER ROLE via EXECUTE (CONTEXT)" 'leakprobe2' \
	"DO \$\$ BEGIN EXECUTE 'ALTER ROLE regress_notify PASSWORD ''leakprobe2'''; END \$\$"
leak_probe "_set_password (chemin de rotate_password)" 'leakprobe3' \
	"SELECT pass_policy._set_password('regress_notify', 'leakprobe3')"
# Un refus n'écrit pas de ligne d'audit (l'ERROR annulerait la transaction) :
# le hook écrit directement une ligne LOG au format de _audit, sans CONTEXT.
n=$(grep -cF 'pg_pass_policy: password_rejected role=regress_notify {"code": "PPP-010"}' "$PPP_TMP/server.log" || true)
check_eq "trois refus journalisés (LOG password_rejected, code seul)" "3" "$n"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE details::text LIKE '%leakprobe%'")
check_eq "aucun mot de passe refusé dans l'audit" "0" "$out"

# ERROR levée par check_password() au lieu d'un motif renvoyé (ici : base
# autre que pg_pass_policy.database, sans l'extension ; PPP-003 depuis la
# vérification 6, le contrôle de la base précédant celui de l'extension) : la
# ligne STATEMENT contiendrait le mot de passe passé en argument. La fonction
# C est déclarée à la main dans une base sans l'extension pour atteindre ce
# chemin.
psql_admin "CREATE DATABASE ppp_noext" >/dev/null
out=$("$PPP_BINDIR/psql" -X -q -At -h 127.0.0.1 -p "$PPP_PORT" -U "$PPP_SUPERUSER" -d ppp_noext \
	-c "CREATE FUNCTION public.ppp_check(text, text) RETURNS text AS 'pg_pass_policy', 'ppp_check_password' LANGUAGE C STRICT" \
	-c "SELECT public.ppp_check('bob', 'LeakProbeUnique-2026')" 2>&1) || true
check_contains "check_password() hors de la base de la politique, sans extension : ERROR PPP-003" 'ERROR: +PPP-003' "$out"
sleep 0.5
n=$(grep -cF -- 'LeakProbeUnique-2026' "$PPP_TMP/server.log" || true)
check_eq "check_password() en erreur : mot de passe absent du log serveur" "0" "$n"

# Extension installée dans une autre base que pg_pass_policy.database : le
# worker n'en maintient jamais les tables, la politique ne s'y applique pas.
# enforce_database = on : PPP-003 comme si l'extension était absente.
psql_admin "CREATE DATABASE ppp_otherdb" >/dev/null
psql_other() {
	"$PPP_BINDIR/psql" -X -q -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PPP_PORT" \
		-U "$PPP_SUPERUSER" -d ppp_otherdb -c "$1" 2>&1
}
psql_other "CREATE EXTENSION pg_pass_policy" >/dev/null
out=$(psql_other "ALTER ROLE regress_notify PASSWORD 'Other-Db#Pass-2026'") || true
check_contains "extension dans une autre base, ALTER ROLE : PPP-003" 'PPP-003' "$out"
out=$(psql_other "SELECT count(*) FROM pass_policy.password_history")
check_eq "autre base : aucun historique écrit" "0" "$out"
# (vérification 6) check_password() et generate_password() suivent le hook :
# hors de pg_pass_policy.database, PPP-003 (check_password() : toujours)
out=$(psql_other "SELECT pass_policy.check_password('regress_notify', 'Other-Db#Check-2026')") || true
check_contains "autre base, check_password() : PPP-003" 'ERROR: +PPP-003' "$out"
out=$(psql_other "SELECT pass_policy.generate_password()") || true
check_contains "autre base, generate_password() : PPP-003 (enforce_database = on)" 'ERROR: +PPP-003' "$out"
# enforce_database = off : WARNING, politique non appliquée (pas d'historique)
psql_admin "ALTER SYSTEM SET pg_pass_policy.enforce_database = off" >/dev/null
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
out=$(psql_other "ALTER ROLE regress_notify PASSWORD 'Other-Db#Pass-2027'") || true
check_contains "enforce_database = off, autre base : WARNING politique non appliquée" 'password policy not applied outside database' "$out"
out=$(psql_other "SELECT count(*) FROM pass_policy.password_history")
check_eq "enforce_database = off, autre base : aucun historique écrit" "0" "$out"
out=$(psql_other "SELECT pass_policy.check_password('regress_notify', 'Other-Db#Check-2027')") || true
check_contains "enforce_database = off, autre base, check_password() : toujours PPP-003" 'ERROR: +PPP-003' "$out"
out=$(psql_other "SELECT length(pass_policy.generate_password())") || true
check_contains "enforce_database = off, autre base, generate_password() : WARNING" 'WARNING: +pg_pass_policy: password policy not applied outside database' "$out"
check_contains "enforce_database = off, autre base, generate_password() : mot de passe produit" '^24$' "$(printf '%s\n' "$out" | grep -v WARNING)"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.enforce_database" >/dev/null
psql_admin "SELECT pg_reload_conf()" >/dev/null

ppp_finish

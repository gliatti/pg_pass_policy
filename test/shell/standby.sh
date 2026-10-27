#!/usr/bin/env bash
# standby.sh — verrous appliqués sur un hot standby (SPEC §6.4, §11)
#
# Primaire temporaire (common.sh) + standby en streaming (pg_basebackup -R,
# second port, même répertoire temporaire, arrêté par le trap EXIT). Le worker
# du standby fait un tour en lecture seule toutes les worker_interval (2 s) :
# il recharge role_state et les profils répliqués dans la shmem locale. Les
# échecs et verrous comptés sur le standby restent en attente et sont écrits
# dans audit_log / role_state par le premier tour qui suit la promotion.
set -euo pipefail
. "$(dirname "$0")/common.sh"

GOOD='Standby-Good#2024'
BAD='Standby-Wrong#2024'
SB_DATA=""
SB_PORT=""

sb_stop() {
	local rc=$?
	if [ -n "$SB_DATA" ] && [ -d "$SB_DATA" ]; then
		"$PPP_BINDIR/pg_ctl" -D "$SB_DATA" -m immediate -w stop >/dev/null 2>&1 || true
		if [ "$rc" -ne 0 ] || [ "$PPP_FAIL" -ne 0 ]; then
			log "fin du log du standby ($PPP_TMP/standby.log) :"
			tail -n 40 "$PPP_TMP/standby.log" 2>/dev/null | sed 's/^/        | /' || true
		fi
	fi
	ppp_stop "$rc"
}
trap sb_stop EXIT

sb_admin() {
	"$PPP_BINDIR/psql" -X -q -At -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$SB_PORT" -U "$PPP_SUPERUSER" -d "$PPP_DB" -c "$1"
}
sb_as() {
	local role=$1 pwd=$2 sql=${3:-SELECT 1}
	PGPASSWORD=$pwd "$PPP_BINDIR/psql" -X -q -At -w -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$SB_PORT" -U "$role" -d "$PPP_DB" -c "$sql" 2>&1
}
# sb_wait_conn SECS ROLE MOTIF : attend que la connexion de ROLE au standby
# produise une sortie correspondant à MOTIF
sb_wait_conn() {
	local timeout=$1 role=$2 pattern=$3 deadline out
	deadline=$((SECONDS + timeout))
	while [ "$SECONDS" -lt "$deadline" ]; do
		out=$(sb_as "$role" "$GOOD" "SELECT current_user") || true
		if printf '%s' "$out" | grep -qE -- "$pattern"; then
			return 0
		fi
		sleep 0.5
	done
	printf '%s\n' "$out"
	return 1
}
# attend que le standby ait rejoué le WAL courant du primaire
sb_catch_up() {
	local lsn
	lsn=$(psql_admin "SELECT pg_current_wal_lsn()")
	local deadline=$((SECONDS + 30))
	while [ "$SECONDS" -lt "$deadline" ]; do
		[ "$(sb_admin "SELECT pg_last_wal_replay_lsn() >= '$lsn'::pg_lsn" 2>/dev/null || true)" = t ] && return 0
		sleep 0.2
	done
	return 1
}

# wait_for_sb SQL : attend que SQL, exécuté sur le standby, renvoie 't' (30 s)
wait_for_sb() {
	local deadline=$((SECONDS + 30))
	while [ "$SECONDS" -lt "$deadline" ]; do
		[ "$(sb_admin "$1" 2>/dev/null || true)" = t ] && return 0
		sleep 0.5
	done
	return 1
}

# attend le worker pg_pass_policy du standby
sb_wait_worker() {
	local deadline=$((SECONDS + $1))
	while [ "$SECONDS" -lt "$deadline" ]; do
		[ "$(sb_admin "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_pass_policy worker'" 2>/dev/null || true)" = 1 ] && return 0
		sleep 0.5
	done
	return 1
}

ppp_start "wal_level = replica" "max_wal_senders = 4" "hot_standby = on"
echo "host replication $PPP_SUPERUSER 127.0.0.1/32 trust" >>"$PPP_TMP/data/pg_hba.conf"
psql_admin "SELECT pg_reload_conf()" >/dev/null

psql_admin "CREATE ROLE regress_sb LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_sb_auto LOGIN PASSWORD '$GOOD'"
psql_admin "SELECT pass_policy.create_profile('p_sb',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": \"1 hour\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_sb_auto', 'p_sb')" >/dev/null

# --- standby en streaming ---------------------------------------------------
SB_DATA=$PPP_TMP/standby
"$PPP_BINDIR/pg_basebackup" -h 127.0.0.1 -p "$PPP_PORT" -U "$PPP_SUPERUSER" \
	-D "$SB_DATA" -R -X stream -c fast >"$PPP_TMP/basebackup.log" 2>&1 || {
	cat "$PPP_TMP/basebackup.log"
	exit 1
}
# hash minimal sur le standby (verrous expirés non audités, voir plus bas)
echo "pg_pass_policy.max_tracked_roles = 16" >>"$SB_DATA/postgresql.conf"
started=0
for attempt in 1 2 3 4 5; do
	SB_PORT=$(ppp_free_port)
	[ "$SB_PORT" = "$PPP_PORT" ] && continue
	rm -f "$PPP_TMP/standby.log"
	if "$PPP_BINDIR/pg_ctl" -D "$SB_DATA" -l "$PPP_TMP/standby.log" \
		-o "-p $SB_PORT" -w -t 60 start >/dev/null 2>&1; then
		started=1
		break
	fi
	grep -q 'Address already in use' "$PPP_TMP/standby.log" 2>/dev/null || break
done
if [ "$started" -ne 1 ]; then
	tail -n 30 "$PPP_TMP/standby.log" || true
	fail "démarrage du standby"
	exit 1
fi
log "standby : port $SB_PORT"
check_eq "le standby est en récupération" "t" "$(sb_admin "SELECT pg_is_in_recovery()")"

if sb_wait_worker 30; then
	ok "le worker tourne sur le standby"
else
	fail "pas de worker sur le standby"
fi

# Fenêtre fail-closed du démarrage (SPEC §6.3) : le cycle standby recharge à
# chaque tour et pose last_reload ; avant, les rôles non exemptés reçoivent
# 57P03 « lock state not loaded yet ».
if wait_for_sb "SELECT last_reload IS NOT NULL FROM pass_policy.worker_status()"; then
	ok "standby : premier rechargement fait (last_reload posé)"
else
	fail "standby : aucun rechargement (last_reload NULL)"
fi
out=$(sb_as regress_sb "$GOOD" "SELECT current_user") || true
check_eq "standby : connexion initiale acceptée" "regress_sb" "$out"

# --- verrou posé sur le primaire -> refusé sur le standby ---------------------
psql_admin "SELECT pass_policy.lock_role('regress_sb', NULL, 'standby test')" >/dev/null
sb_catch_up || fail "le standby n'a pas rejoué le verrou"
# au plus 2 tours du worker (worker_interval = 2 s) + marge
if out=$(sb_wait_conn 6 regress_sb "is locked by pg_pass_policy"); then
	ok "lock_role sur le primaire : connexion refusée sur le standby"
else
	fail "lock_role sur le primaire : le standby accepte toujours la connexion" "$out"
fi
out=$(sb_admin "SELECT locked_until FROM pass_policy.failed_attempts() WHERE role_name = 'regress_sb'")
check_eq "standby : failed_attempts() montre le verrou" "infinity" "$out"

# --- unlock sur le primaire -> accepté sur le standby -------------------------
psql_admin "SELECT pass_policy.unlock_role('regress_sb')" >/dev/null
sb_catch_up || fail "le standby n'a pas rejoué le déverrouillage"
if out=$(sb_wait_conn 6 regress_sb "^regress_sb$"); then
	ok "unlock_role sur le primaire : connexion acceptée sur le standby"
else
	fail "unlock_role sur le primaire : toujours refusé sur le standby" "$out"
fi

# --- verrou temporisé (lock_role avec durée) ----------------------------------
psql_admin "SELECT pass_policy.lock_role('regress_sb', interval '1 hour', 'timed')" >/dev/null
sb_catch_up || true
if out=$(sb_wait_conn 6 regress_sb "is locked by pg_pass_policy"); then
	ok "verrou temporisé du primaire appliqué sur le standby"
else
	fail "verrou temporisé non appliqué sur le standby" "$out"
fi
psql_admin "SELECT pass_policy.unlock_role('regress_sb')" >/dev/null
sb_catch_up || true
sb_wait_conn 6 regress_sb "^regress_sb$" >/dev/null || fail "regress_sb pas déverrouillé sur le standby"

# --- verrou automatique du primaire (copié dans role_state par le worker) -----
for i in 1 2; do psql_as regress_sb_auto "$BAD" >/dev/null || true; done
wait_for 30 "SELECT coalesce((SELECT locked_until IS NOT NULL FROM pass_policy.role_state WHERE role_name = 'regress_sb_auto'), false)" ||
	fail "verrou automatique non copié dans role_state sur le primaire"
sb_catch_up || true
if out=$(sb_wait_conn 6 regress_sb_auto "is locked by pg_pass_policy"); then
	ok "verrou automatique du primaire appliqué sur le standby"
else
	fail "verrou automatique du primaire non appliqué sur le standby" "$out"
fi
psql_admin "SELECT pass_policy.unlock_role('regress_sb_auto')" >/dev/null
sb_catch_up || true
sb_wait_conn 6 regress_sb_auto "^regress_sb_auto$" >/dev/null &&
	ok "verrou automatique levé sur le primaire : accepté sur le standby" ||
	fail "verrou automatique levé sur le primaire : toujours refusé sur le standby"

# --- profil répliqué : échecs comptés localement sur le standby ---------------
# p_sb (max_failures = 2) est chargé par le worker du standby : 2 échecs sur le
# standby y verrouillent le rôle (verrou local, non écrit dans role_state).
for i in 1 2; do sb_as regress_sb_auto "$BAD" >/dev/null || true; done
out=$(sb_as regress_sb_auto "$GOOD") || true
check_contains "standby : profil répliqué appliqué (2 échecs -> verrou local)" "is locked by pg_pass_policy" "$out"
sleep 3 # un tour du worker du standby ne lève pas un verrou local
out=$(sb_as regress_sb_auto "$GOOD") || true
check_contains "standby : le verrou local survit au rechargement" "is locked by pg_pass_policy" "$out"
out=$(psql_as regress_sb_auto "$GOOD" "SELECT current_user") || true
check_eq "primaire : le verrou local du standby ne s'y applique pas" "regress_sb_auto" "$out"
# un superutilisateur peut lever un verrou local sur le standby
sb_admin "SELECT pass_policy.shmem_unlock_role('regress_sb_auto')" >/dev/null
out=$(sb_as regress_sb_auto "$GOOD" "SELECT current_user") || true
check_eq "standby : shmem_unlock_role() lève le verrou local" "regress_sb_auto" "$out"

# --- standby : verrous expirés non audités évincables (revue finale 2, F3) ---
# L'audit role_locked d'un verrou posé sur le standby ne peut pas être écrit
# avant une promotion. Une fois le verrou expiré, l'entrée doit redevenir
# évincable : sinon 16 vrais rôles verrouillés une fois rempliraient le hash
# (max_tracked_roles = 16 sur le standby) et les échecs d'un 17e rôle ne
# seraient plus comptés. Les profils gardent leur entrée : on passe par le
# profil default (2 échecs, verrou de 1 s), rétabli ensuite.
psql_admin "SELECT pass_policy.alter_profile('default', '{\"max_failures\": 2, \"lock_duration\": \"1 second\"}')" >/dev/null
for n in $(seq -w 1 16); do
	psql_admin "CREATE ROLE regress_sb_f$n LOGIN PASSWORD '$GOOD'"
done
sb_catch_up || fail "F3 : le standby n'a pas rejoué les rôles"
sleep 3 # rechargement forcé à chaque tour du worker du standby (2 s)
for n in $(seq -w 1 15); do
	for i in 1 2; do sb_as "regress_sb_f$n" "$BAD" >/dev/null || true; done
done
out=$(sb_admin "SELECT tracked_roles FROM pass_policy.worker_status()")
check_eq "F3 : hash du standby plein (16 entrées)" "16" "$out"
sleep 2 # les verrous de 1 s expirent ; leur audit reste en attente
for i in 1 2; do sb_as regress_sb_f16 "$BAD" >/dev/null || true; done
out=$(sb_as regress_sb_f16 "$GOOD") || true
check_contains "F3 : 17e rôle compté et verrouillé (un verrou expiré non audité a été évincé)" "is locked by pg_pass_policy" "$out"
n=$(grep -c 'cannot track authentication failures of role "regress_sb_f16"' "$PPP_TMP/standby.log" || true)
check_eq "F3 : aucun refus de comptage pour le 17e rôle" "0" "$n"
n=$(grep -c 'evicted before its lock was audited' "$PPP_TMP/standby.log" || true)
check_eq "F3 : perte d'audit journalisée (LOG)" "1" "$( [ "$n" -ge 1 ] && echo 1 || echo 0)"
psql_admin "SELECT pass_policy.alter_profile('default', '{\"max_failures\": 5, \"lock_duration\": \"30 minutes\"}')" >/dev/null

# --- lecture seule : aucune erreur d'écriture du worker du standby -----------
n=$(grep -cE 'pg_pass_policy: worker .* failed|read-only transaction' "$PPP_TMP/standby.log" || true)
check_eq "standby : aucun échec de cycle du worker (aucune écriture tentée)" "0" "$n"
n=$(grep -c 'pg_pass_policy: worker .* failed' "$PPP_TMP/server.log" || true)
check_eq "primaire : aucun échec de cycle du worker" "0" "$n"

# --- promotion : les verrous locaux du standby sont audités ------------------
n_locked_before=$(sb_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_sb_auto'")
for i in 1 2; do sb_as regress_sb_auto "$BAD" >/dev/null || true; done
out=$(sb_as regress_sb_auto "$GOOD") || true
check_contains "standby : nouveau verrou local avant promotion" "is locked by pg_pass_policy" "$out"
sleep 3 # un tour du worker du standby : rien n'est acquitté
n=$(grep -c 'not written to the audit log' "$PPP_TMP/standby.log" || true)
check_eq "standby : échecs et verrous locaux non acquittés (restent en attente)" "0" "$n"
"$PPP_BINDIR/pg_ctl" -D "$SB_DATA" -w -t 60 promote >/dev/null
if wait_for_sb "SELECT NOT pg_is_in_recovery()"; then
	ok "standby promu"
else
	fail "le standby n'a pas été promu"
fi
if wait_for_sb "SELECT coalesce((SELECT locked_until > now() AND locked_by = 'auto' FROM pass_policy.role_state WHERE role_name = 'regress_sb_auto'), false)"; then
	ok "nouveau primaire : verrou local du standby copié dans role_state"
else
	fail "nouveau primaire : role_state ne contient pas le verrou" "$(sb_admin "SELECT * FROM pass_policy.role_state WHERE role_name = 'regress_sb_auto'")"
fi
n_locked_after=$(sb_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_sb_auto'")
check_eq "nouveau primaire : audit role_locked du verrou local écrit" "1" "$( [ "$n_locked_after" -gt "$n_locked_before" ] && echo 1 || echo 0)"
# Deux verrous locaux sur le standby (le premier levé par shmem_unlock_role()
# avant promotion) : une seule ligne est écrite, pour le dernier, et elle
# compte l'épisode antérieur resté sans ligne (revue finale 3)
out=$(sb_admin "SELECT details->>'lost_episodes' FROM pass_policy.audit_log
                 WHERE event_type = 'role_locked' AND role_name = 'regress_sb_auto'
                 ORDER BY id DESC LIMIT 1")
check_eq "nouveau primaire : épisode de verrouillage antérieur compté (lost_episodes)" "1" "$out"
out=$(sb_admin "SELECT coalesce(sum((details->>'count')::int), 0) >= 2 FROM pass_policy.audit_log
                 WHERE event_type = 'auth_failed' AND role_name = 'regress_sb_auto' AND event_time > now() - interval '1 minute'")
check_eq "nouveau primaire : échecs comptés sur le standby audités (auth_failed)" "t" "$out"
out=$(sb_as regress_sb_auto "$GOOD") || true
check_contains "nouveau primaire : le rôle reste verrouillé" "is locked by pg_pass_policy" "$out"
n=$(grep -c 'pg_pass_policy: worker .* failed' "$PPP_TMP/standby.log" || true)
check_eq "nouveau primaire : aucun échec de cycle du worker" "0" "$n"

ppp_finish

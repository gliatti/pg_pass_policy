#!/usr/bin/env bash
# hashfull.sh — hash shmem plein : les verrous restent appliqués (fail-closed)
# (SPEC §6.3, §11)
#
# max_tracked_roles = 16 (minimum du GUC) : 15 entrées au plus pour le simple
# comptage d'échecs par le hook d'authentification, 1 réservée aux verrous et
# aux profils. Un client non authentifié qui essaie des noms inexistants ne
# doit empêcher ni lock_role(), ni la réinjection des verrous de role_state,
# ni le comptage des échecs d'un vrai rôle ; quand toutes les entrées sont des
# verrous, lock_role() doit échouer par une ERROR (et non un WARNING).
set -euo pipefail
. "$(dirname "$0")/common.sh"

GOOD='Hashfull-Good#2024'
BAD='Hashfull-Wrong#2024'
MAX=16
LIMIT=15

ppp_start "pg_pass_policy.max_tracked_roles = $MAX"

# n tentatives avec des noms inexistants et un mauvais mot de passe
flood() {
	local prefix=$1 n=$2 i
	for i in $(seq 1 "$n"); do psql_as "${prefix}_$i" "$BAD" >/dev/null || true; done
}
n_entries() { psql_admin "SELECT count(*) FROM pass_policy.failed_attempts()"; }
n_locked() { psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE locked_until IS NOT NULL"; }

psql_admin "CREATE ROLE victime LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_bf LOGIN PASSWORD '$GOOD'"
wait_worker_run 30 || true

# --- remplissage par des noms inexistants -----------------------------------
flood ghost 24
n=$(n_entries)
check_eq "24 noms inexistants : au plus $LIMIT entrées de comptage (réserve de 10 %)" "1" "$( [ "$n" -le "$LIMIT" ] && echo 1 || echo 0)"
check_contains "hook : refus de créer une entrée journalisé (LOG)" "cannot track authentication failures of role \"ghost_" "$(cat "$PPP_TMP/server.log")"

# --- lock_role trouve toujours une place ------------------------------------
out=$(psql_admin "SELECT pass_policy.lock_role('victime', NULL, 'hashfull')" 2>&1) || true
check_not_contains "lock_role : aucun WARNING « too many tracked roles »" "too many tracked roles|WARNING" "$out"
out=$(psql_as victime "$GOOD") || true
check_contains "hash plein de noms inexistants : la victime verrouillée est refusée" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT failed_count, locked_until FROM pass_policy.failed_attempts() WHERE role_name = 'victime'")
check_eq "failed_attempts() : verrou de la victime présent en shmem" "0|infinity" "$out"
out=$(psql_admin "SELECT locked_until FROM pass_policy.role_state WHERE role_name = 'victime'")
check_eq "role_state cohérent avec la shmem" "infinity" "$out"
wait_worker_run 30 || true
flood ghost2 24
out=$(psql_as victime "$GOOD") || true
check_contains "après un tour du worker et un nouveau remplissage : toujours refusée" "is locked by pg_pass_policy" "$out"

# --- réinjection depuis role_state après redémarrage, hash rempli -----------
"$PPP_BINDIR/pg_ctl" -D "$PPP_TMP/data" -l "$PPP_TMP/server.log" -o "-p $PPP_PORT" -w -t 60 restart >/dev/null
flood ghost3 24
wait_worker_run 30 || fail "pas de tour du worker après le redémarrage"
flood ghost4 24
out=$(psql_as victime "$GOOD") || true
check_contains "redémarrage + remplissage : verrou réinjecté depuis role_state" "is locked by pg_pass_policy" "$out"
n=$(grep -c 'could not be loaded in shared memory' "$PPP_TMP/server.log" || true)
check_eq "aucun « could not be loaded » (réinjection jamais abandonnée)" "0" "$n"

# --- le comptage d'un vrai rôle n'est pas empêché par le remplissage --------
# Les entrées des noms inexistants, une fois marquées par le worker
# (role_missing), sont évincées en priorité par le hook.
wait_worker_run 30 || true
for i in 1 2 3 4 5; do psql_as regress_bf "$BAD" >/dev/null || true; done
out=$(psql_as regress_bf "$GOOD") || true
check_contains "hash plein : 5 échecs sur un vrai rôle le verrouillent quand même" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_bf'")
check_eq "failed_attempts() : compteur du vrai rôle = 5" "5" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_bf')" >/dev/null

# --- purge des noms inexistants après failure_window (et non 24 h) ----------
psql_admin "SELECT pass_policy.alter_profile('default', '{\"failure_window\": \"2 seconds\"}')" >/dev/null
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
wait_for 30 "SELECT coalesce(max(last_reload) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" ||
	fail "pas de rechargement après alter_profile(default)"
flood ghost5 10
sleep 3
if wait_for 30 "SELECT count(*) = 0 FROM pass_policy.failed_attempts() WHERE role_name LIKE 'ghost%'"; then
	ok "entrées de rôles inexistants purgées après failure_window"
else
	fail "entrées de rôles inexistants non purgées" "$(psql_admin "SELECT * FROM pass_policy.failed_attempts()")"
fi
out=$(psql_admin "SELECT locked_until FROM pass_policy.failed_attempts() WHERE role_name = 'victime'")
check_eq "la purge ne touche pas au verrou de la victime" "infinity" "$out"

# --- toutes les entrées sont des verrous : lock_role lève une ERROR ---------
flood ghost6 24
locked=$(n_locked)
need=$((MAX - locked))
for i in $(seq 1 $((need + 1))); do
	psql_admin "CREATE ROLE regress_l$i LOGIN PASSWORD '$GOOD'"
done
errs=0
for i in $(seq 1 "$need"); do
	psql_admin "SELECT pass_policy.lock_role('regress_l$i', NULL, 'fill')" >/dev/null 2>&1 || errs=$((errs + 1))
done
check_eq "$need verrous supplémentaires acceptés (ils évincent les noms inexistants)" "0" "$errs"
check_eq "les $MAX entrées sont des verrous" "$MAX" "$(n_locked)"
last=regress_l$((need + 1))
out=$(psql_admin "SELECT pass_policy.lock_role('$last', NULL, 'one too many')" 2>&1) && rc=0 || rc=$?
check_eq "lock_role sur un hash plein de verrous : échec" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "message d'erreur explicite" "ERROR: +cannot lock role \"$last\": pg_pass_policy shared memory is full" "$out"
out=$(psql_admin "SELECT coalesce((SELECT locked_until IS NULL FROM pass_policy.role_state WHERE role_name = '$last'), true)")
check_eq "transaction annulée : role_state ne prétend pas que $last est verrouillé" "t" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = '$last'")
check_eq "transaction annulée : pas d'audit role_locked pour $last" "0" "$out"
out=$(psql_as "$last" "$GOOD" "SELECT current_user") || true
check_eq "$last n'est pas verrouillé (cohérent avec role_state)" "$last" "$out"
out=$(psql_as regress_l1 "$GOOD") || true
check_contains "les verrous existants restent appliqués" "is locked by pg_pass_policy" "$out"
out=$(psql_as ghost7_1 "$BAD") || true
check_contains "hash plein de verrous : le hook refuse toujours (mauvais mot de passe)" "password authentication failed" "$out"
out=$(psql_admin "SELECT 1")
check_eq "le serveur répond" "1" "$out"

# un déverrouillage libère une entrée évincable : lock_role réussit ensuite
psql_admin "SELECT pass_policy.unlock_role('regress_l1')" >/dev/null
out=$(psql_admin "SELECT pass_policy.lock_role('$last', NULL, 'room again')" 2>&1) && rc=0 || rc=$?
check_eq "après unlock_role d'un autre rôle : lock_role réussit" "0" "$rc"
out=$(psql_as "$last" "$GOOD") || true
check_contains "$last désormais refusé" "is locked by pg_pass_policy" "$out"
out=$(psql_as regress_l1 "$GOOD" "SELECT current_user") || true
check_eq "regress_l1 déverrouillé (entrée évincée sans conséquence)" "regress_l1" "$out"

n=$(grep -c 'pg_pass_policy: worker .* failed' "$PPP_TMP/server.log" || true)
check_eq "aucun échec de cycle du worker dans le log" "0" "$n"

ppp_finish

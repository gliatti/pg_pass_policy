#!/usr/bin/env bash
# hashfull.sh — hash shmem plein : verrous et comptage restent appliqués
# (fail-closed, SPEC §6.3, §11)
#
# max_tracked_roles = 16 (minimum du GUC), aucune réserve. Le hook vérifie
# lui-même l'existence du rôle : les entrées des noms inexistants (fantômes)
# sont toujours évincables, si bien qu'un client non authentifié qui essaie
# des noms inexistants ne peut empêcher ni lock_role(), ni la réinjection des
# verrous de role_state, ni le comptage des échecs d'un vrai rôle, et cela
# sans attendre un tour du worker (worker_interval = 3600 : le worker ne
# tourne que lorsqu'on le réveille). Quand toutes les entrées sont des verrous
# de vrais rôles, lock_role() échoue par une ERROR 53400 et sa transaction est
# annulée.
set -euo pipefail
. "$(dirname "$0")/common.sh"

GOOD='Hashfull-Good#2024'
BAD='Hashfull-Wrong#2024'
MAX=16

ppp_start "pg_pass_policy.max_tracked_roles = $MAX" "pg_pass_policy.worker_interval = 3600"

# n tentatives avec des noms inexistants et un mauvais mot de passe
flood() {
	local prefix=$1 n=$2 i
	for i in $(seq 1 "$n"); do psql_as "${prefix}_$i" "$BAD" >/dev/null || true; done
}
n_entries() { psql_admin "SELECT count(*) FROM pass_policy.failed_attempts()"; }
# verrous de vrais rôles (les fantômes s'appellent ghost* ou phantom*)
n_real_locked() {
	psql_admin "SELECT count(*) FROM pass_policy.failed_attempts()
	             WHERE locked_until IS NOT NULL AND role_name NOT LIKE 'ghost%' AND role_name NOT LIKE 'phantom%'"
}
# réveille le worker (shmem_reload au COMMIT) et attend la fin de son tour
kick() {
	local t0
	t0=$(psql_admin "SELECT clock_timestamp()")
	psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
	wait_for 30 "SELECT coalesce(max(last_reload) > '$t0'::timestamptz AND max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()"
}
n_log() { grep -c -- "$1" "$PPP_TMP/server.log" || true; }

psql_admin "CREATE ROLE victime LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_bf LOGIN PASSWORD '$GOOD'"
kick || fail "pas de tour initial du worker"

# --- remplissage par des noms inexistants : plus de réserve ------------------
flood ghost 24
check_eq "24 noms inexistants : les $MAX entrées sont occupées (aucune réserve)" "$MAX" "$(n_entries)"
check_eq "hook : aucune entrée refusée (les fantômes s'évincent entre eux)" "0" "$(n_log 'cannot track authentication failures')"

# --- défaut n° 1 : un vrai rôle est compté immédiatement --------------------
for i in 1 2 3 4 5; do psql_as regress_bf "$BAD" >/dev/null || true; done
out=$(psql_as regress_bf "$GOOD") || true
check_contains "16 fantômes puis 5 échecs sur un vrai rôle : verrouillé sans tour du worker" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_bf'")
check_eq "failed_attempts() : compteur du vrai rôle = 5" "5" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_bf')" >/dev/null

# --- verrou automatique levé avant le passage du worker : audit conservé -----
# unlock_role() arrive avant que le worker ait écrit role_locked : le verrou
# doit être audité quand même (role_locked ET role_unlocked), sans être recopié
# dans role_state (le rôle reste déverrouillé).
psql_admin "CREATE ROLE regress_e3 LOGIN PASSWORD '$GOOD'"
for i in 1 2 3 4 5; do psql_as regress_e3 "$BAD" >/dev/null || true; done
out=$(psql_as regress_e3 "$GOOD") || true
check_contains "regress_e3 verrouillé automatiquement (5 échecs)" "is locked by pg_pass_policy" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_e3')" >/dev/null
kick || fail "pas de tour du worker après unlock_role(regress_e3)"
out=$(psql_admin "SELECT string_agg(event_type || ':' || coalesce(details->>'locked_by', details->>'by', '?'), ',' ORDER BY event_type)
                    FROM pass_policy.audit_log
                   WHERE role_name = 'regress_e3' AND event_type IN ('role_locked', 'role_unlocked')")
check_eq "audit : role_locked (auto) ET role_unlocked (manual)" "role_locked:auto,role_unlocked:manual" "$out"
out=$(psql_admin "SELECT details->>'lifted_before_audit' FROM pass_policy.audit_log
                   WHERE role_name = 'regress_e3' AND event_type = 'role_locked'")
check_eq "role_locked marqué lifted_before_audit" "true" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_state WHERE role_name = 'regress_e3' AND locked_until IS NOT NULL")
check_eq "role_state : le verrou levé n'est pas recopié" "0" "$out"
out=$(psql_as regress_e3 "$GOOD" "SELECT current_user") || true
check_eq "regress_e3 se connecte après le tour du worker" "regress_e3" "$out"

# --- un nom inexistant est « verrouillé » comme un vrai rôle -----------------
flood ghost_b 24
for i in 1 2 3 4 5; do psql_as phantom "$BAD" >/dev/null || true; done
out=$(psql_as phantom "$BAD") || true
check_contains "nom inexistant : « locked » après 5 échecs, comme un vrai rôle" "FATAL: +role \"phantom\" is locked by pg_pass_policy" "$out"
for i in 1 2 3 4 5; do psql_as regress_bf "$BAD" >/dev/null || true; done
out_real=$(psql_as regress_bf "$BAD") || true
norm() { printf '%s' "$1" | sed -E 's/"(phantom|regress_bf)"/"X"/g; s/port [0-9]+/port N/; s/until .*/until T/'; }
check_eq "réponse identique pour un nom inexistant et un vrai rôle (pas d'oracle)" "$(norm "$out_real")" "$(norm "$out")"
psql_admin "SELECT pass_policy.unlock_role('regress_bf')" >/dev/null

# --- lock_role trouve toujours une place ------------------------------------
flood ghost_c 24
out=$(psql_admin "SELECT pass_policy.lock_role('victime', NULL, 'hashfull')" 2>&1) || true
check_not_contains "lock_role : aucun WARNING" "too many tracked roles|WARNING|ERROR" "$out"
out=$(psql_as victime "$GOOD") || true
check_contains "hash plein de noms inexistants : la victime verrouillée est refusée" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT failed_count, locked_until FROM pass_policy.failed_attempts() WHERE role_name = 'victime'")
check_eq "failed_attempts() : verrou de la victime présent en shmem" "0|infinity" "$out"
out=$(psql_admin "SELECT locked_until FROM pass_policy.role_state WHERE role_name = 'victime'")
check_eq "role_state cohérent avec la shmem" "infinity" "$out"
kick || fail "pas de tour du worker après lock_role"
flood ghost2 24
out=$(psql_as victime "$GOOD") || true
check_contains "après un tour du worker et un nouveau remplissage : toujours refusée" "is locked by pg_pass_policy" "$out"

# --- réinjection depuis role_state après redémarrage, hash rempli -----------
"$PPP_BINDIR/pg_ctl" -D "$PPP_TMP/data" -l "$PPP_TMP/server.log" -o "-p $PPP_PORT" -w -t 60 restart >/dev/null
flood ghost3 24
kick || fail "pas de tour du worker après le redémarrage"
flood ghost4 24
out=$(psql_as victime "$GOOD") || true
check_contains "redémarrage + remplissage : verrou réinjecté depuis role_state" "is locked by pg_pass_policy" "$out"
check_eq "aucun « could not be loaded » (réinjection jamais abandonnée)" "0" "$(n_log 'could not be loaded in shared memory')"

# --- purge des noms inexistants après failure_window (et non 24 h) ----------
psql_admin "SELECT pass_policy.alter_profile('default', '{\"failure_window\": \"2 seconds\"}')" >/dev/null
kick || fail "pas de rechargement après alter_profile(default)"
flood ghost5 10
sleep 3
kick || true
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name LIKE 'ghost%' OR role_name LIKE 'phantom%'")
check_eq "entrées de rôles inexistants purgées après failure_window" "0" "$out"
out=$(psql_admin "SELECT locked_until FROM pass_policy.failed_attempts() WHERE role_name = 'victime'")
check_eq "la purge ne touche pas au verrou de la victime" "infinity" "$out"
psql_admin "SELECT pass_policy.alter_profile('default', '{\"failure_window\": \"15 minutes\"}')" >/dev/null
kick || true

# --- toutes les entrées sont des verrous de vrais rôles : ERROR 53400 -------
flood ghost6 24
need=$((MAX - $(n_real_locked)))
for i in $(seq 1 $((need + 1))); do
	psql_admin "CREATE ROLE regress_l$i LOGIN PASSWORD '$GOOD'"
done
errs=0
for i in $(seq 1 "$need"); do
	psql_admin "SELECT pass_policy.lock_role('regress_l$i', NULL, 'fill')" >/dev/null 2>&1 || errs=$((errs + 1))
done
check_eq "$need verrous supplémentaires acceptés (ils évincent les noms inexistants)" "0" "$errs"
check_eq "les $MAX entrées sont des verrous de vrais rôles" "$MAX" "$(n_real_locked)"
last=regress_l$((need + 1))
psql_admin "SELECT pass_policy.run_maintenance()" >/dev/null # crée la ligne role_state de $last
state_before=$(psql_admin "SELECT s::text FROM pass_policy.role_state s WHERE role_name = '$last'")
out=$(printf '%s\n' "\\set VERBOSITY verbose" "SELECT pass_policy.lock_role('$last', NULL, 'one too many');" | psql_admin_script) && rc=0 || rc=$?
check_eq "lock_role sur un hash plein de verrous : échec" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "ERROR 53400 explicite" "ERROR: +53400: cannot lock role \"$last\": pg_pass_policy shared memory is full" "$out"
state_after=$(psql_admin "SELECT s::text FROM pass_policy.role_state s WHERE role_name = '$last'")
check_eq "transaction annulée : ligne role_state de $last inchangée" "$state_before" "$state_after"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = '$last'")
check_eq "transaction annulée : pas d'audit role_locked pour $last" "0" "$out"
out=$(psql_as "$last" "$GOOD" "SELECT current_user") || true
check_eq "$last n'est pas verrouillé (cohérent avec role_state)" "$last" "$out"
out=$(psql_as regress_l1 "$GOOD") || true
check_contains "les verrous existants restent appliqués" "is locked by pg_pass_policy" "$out"

# hook sur un hash plein de verrous : refus normal, LOG au plus une fois par seconde
n0=$(n_log 'cannot track authentication failures')
t_start=$(date +%s%N)
flood ghost7 20
t_ms=$((($(date +%s%N) - t_start) / 1000000))
n1=$(($(n_log 'cannot track authentication failures') - n0))
out=$(psql_as ghost7_1 "$BAD") || true
check_contains "hash plein de verrous : le hook refuse toujours (mauvais mot de passe)" "password authentication failed" "$out"
check_eq "LOG « cannot track » émis ($n1 en $t_ms ms, au plus 1 par seconde)" "1" \
	"$( [ "$n1" -ge 1 ] && [ "$n1" -le $((t_ms / 1000 + 1)) ] && echo 1 || echo 0)"
check_eq "le serveur répond" "1" "$(psql_admin "SELECT 1")"

# un déverrouillage libère une entrée évincable : lock_role réussit ensuite
psql_admin "SELECT pass_policy.unlock_role('regress_l1')" >/dev/null
out=$(psql_admin "SELECT pass_policy.lock_role('$last', NULL, 'room again')" 2>&1) && rc=0 || rc=$?
check_eq "après unlock_role d'un autre rôle : lock_role réussit" "0" "$rc"
out=$(psql_as "$last" "$GOOD") || true
check_contains "$last désormais refusé" "is locked by pg_pass_policy" "$out"
out=$(psql_as regress_l1 "$GOOD" "SELECT current_user") || true
check_eq "regress_l1 déverrouillé (entrée évincée sans conséquence)" "regress_l1" "$out"

# --- lock_role annulé faute de place : la victime évincée est restaurée ------
# Une seule entrée évincable (compteur vivant de regress_l2, déverrouillé puis
# en échec) : une transaction verrouille A puis B ; A prend la place de
# regress_l2, B n'en trouve pas → ERROR 53400, et l'annulation doit remettre
# le compteur de regress_l2 (avant correction, il était perdu).
psql_admin "SELECT pass_policy.unlock_role('regress_l2')" >/dev/null
for i in 1 2; do psql_as regress_l2 "$BAD" >/dev/null || true; done
check_eq "regress_l2 : compteur vivant = 2 (seule entrée évincable)" "2" \
	"$(psql_admin "SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_l2'")"
psql_admin "CREATE ROLE regress_e5a LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_e5b LOGIN PASSWORD '$GOOD'"
out=$(printf '%s\n' "BEGIN;" "SELECT pass_policy.lock_role('regress_e5a', NULL, 'e5');" \
	"SELECT pass_policy.lock_role('regress_e5b', NULL, 'e5');" "COMMIT;" | psql_admin_script) && rc=0 || rc=$?
check_contains "verrou de A puis B sans place pour B : ERROR 53400" "cannot lock role \"regress_e5b\": pg_pass_policy shared memory is full" "$out"
check_eq "compteur de regress_l2 intact après l'annulation" "2" \
	"$(psql_admin "SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_l2'")"
check_eq "aucun verrou en shmem pour A ni B" "0" \
	"$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name IN ('regress_e5a', 'regress_e5b')")"
out=$(psql_as regress_e5a "$GOOD" "SELECT current_user") || true
check_eq "A n'est pas verrouillé" "regress_e5a" "$out"
for i in 3 4 5; do psql_as regress_l2 "$BAD" >/dev/null || true; done
out=$(psql_as regress_l2 "$GOOD") || true
check_contains "le compteur restauré mène au verrou au 5e échec" "is locked by pg_pass_policy" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_l2')" >/dev/null

# --- profils sur 15 rôles sur 16 : un 16e rôle sans profil est compté -------
psql_admin "SELECT pass_policy.unlock_role(r) FROM unnest(ARRAY['victime', '$last']
              || ARRAY(SELECT 'regress_l' || i FROM generate_series(2, $need) i)) r" >/dev/null
psql_admin "SELECT pass_policy.create_profile('p_hf',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": \"1 hour\", \"min_age\": \"0\"}')" >/dev/null
for i in $(seq 1 15); do
	psql_admin "CREATE ROLE regress_p$i LOGIN PASSWORD '$GOOD'"
	psql_admin "SELECT pass_policy.assign_profile('regress_p$i', 'p_hf')" >/dev/null
done
psql_admin "CREATE ROLE regress_np LOGIN PASSWORD '$GOOD'"
kick || fail "pas de rechargement après assign_profile"
check_eq "15 profils chargés sans « could not be loaded »" "0" "$(n_log 'could not be loaded in shared memory')"
for i in 1 2; do psql_as regress_p15 "$BAD" >/dev/null || true; done
out=$(psql_as regress_p15 "$GOOD") || true
check_contains "profil p_hf (max_failures = 2) appliqué au 15e rôle" "is locked by pg_pass_policy" "$out"
flood ghost8 24
for i in 1 2 3 4 5; do psql_as regress_np "$BAD" >/dev/null || true; done
out=$(psql_as regress_np "$GOOD") || true
check_contains "15 profils + fantômes : le 16e rôle, sans profil, est compté et verrouillé" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_np'")
check_eq "failed_attempts() : compteur du 16e rôle = 5" "5" "$out"

check_eq "aucun échec de cycle du worker dans le log" "0" "$(n_log 'pg_pass_policy: worker .* failed')"

ppp_finish

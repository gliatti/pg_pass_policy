#!/usr/bin/env bash
# lockout.sh — verrouillage après N échecs d'authentification (SPEC §6.3, §7, §11)
#
# Vraies connexions TCP en SCRAM. Le mauvais mot de passe est toujours fourni
# explicitement (PGPASSWORD) : une connexion abandonnée avant l'envoi du mot
# de passe (STATUS_EOF) n'est pas comptée (SPEC §11).
set -euo pipefail
. "$(dirname "$0")/common.sh"

GOOD='Lockout-Good#2024'
BAD='Lockout-Wrong#2024'

# shellcheck disable=SC2119 # pas de surcharge de configuration
ppp_start

psql_admin "SELECT pass_policy.create_profile('p_lock',
  '{\"max_failures\": 5, \"failure_window\": \"1 minute\", \"lock_duration\": \"5 seconds\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_lock LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_lock', 'p_lock')" >/dev/null
if wait_for 30 "SELECT coalesce(max(last_reload) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()"; then
	ok "le worker recharge les paramètres après assign_profile"
else
	fail "le worker n'a pas rechargé les paramètres (worker_status.last_reload)"
fi

out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "connexion initiale avec le bon mot de passe" "regress_lock" "$out"

# --- 5 échecs puis refus même avec le bon mot de passe ------------------------
for i in 1 2 3 4 5; do
	out=$(psql_as regress_lock "$BAD") && fail "échec $i : connexion acceptée avec un mauvais mot de passe" || true
	check_contains "échec $i : authentification refusée" "password authentication failed" "$out"
done
out=$(psql_as regress_lock "$GOOD") && rc=0 || rc=$?
check_eq "6e tentative (bon mot de passe) refusée" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "message « locked »" "locked" "$out"
check_not_contains "le message ne contient pas le mot de passe" "$GOOD" "$out"

out=$(psql_admin "SELECT failed_count >= 5, locked_until IS NOT NULL FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock'")
check_eq "failed_attempts() : compteur >= 5 et verrou posé" "t|t" "$out"

if wait_for 30 "SELECT count(*) > 0 FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_lock'"; then
	ok "audit role_locked écrit par le worker"
else
	fail "pas d'audit role_locked"
fi
if wait_for 30 "SELECT count(*) > 0 FROM pass_policy.audit_log WHERE event_type = 'auth_failed' AND role_name = 'regress_lock'"; then
	ok "audit auth_failed écrit par le worker"
else
	fail "pas d'audit auth_failed"
fi
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE details::text LIKE '%$GOOD%' OR details::text LIKE '%$BAD%'")
check_eq "aucun mot de passe dans l'audit" "0" "$out"

# --- déverrouillage automatique après lock_duration (5 s) ---------------------
sleep 6
psql_admin "SELECT count(*) FROM pass_policy.run_maintenance()" >/dev/null
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "connexion acceptée après expiration du verrou" "regress_lock" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock' AND locked_until > now()")
check_eq "plus de verrou actif en shmem" "0" "$out"
out=$(psql_admin "SELECT locked_until IS NULL FROM pass_policy.role_state WHERE role_name = 'regress_lock'")
check_eq "role_state.locked_until effacé" "t" "$out"

# --- un succès remet le compteur à zéro --------------------------------------
for i in 1 2 3; do psql_as regress_lock "$BAD" >/dev/null || true; done
psql_as regress_lock "$GOOD" >/dev/null || true
for i in 1 2 3; do psql_as regress_lock "$BAD" >/dev/null || true; done
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "3 échecs + succès + 3 échecs : pas de verrou" "regress_lock" "$out"

# --- fenêtre d'échecs (failure_window) ---------------------------------------
psql_admin "SELECT pass_policy.alter_profile('p_lock', '{\"failure_window\": \"2 seconds\"}')" >/dev/null
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
wait_for 30 "SELECT coalesce(max(last_reload) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || true
for i in 1 2 3 4; do psql_as regress_lock "$BAD" >/dev/null || true; done
sleep 3
for i in 1 2 3 4; do psql_as regress_lock "$BAD" >/dev/null || true; done
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "4 + 4 échecs séparés de plus que failure_window : pas de verrou" "regress_lock" "$out"

# --- verrou manuel / unlock_role ----------------------------------------------
psql_admin "SELECT pass_policy.lock_role('regress_lock', NULL, 'shell test')" >/dev/null
out=$(psql_as regress_lock "$GOOD") && rc=0 || rc=$?
check_contains "lock_role manuel : connexion refusée (locked)" "locked" "$out"
# Le verrou manuel survit à un rechargement de la shmem par le worker
psql_admin "SELECT count(*) FROM pass_policy.run_maintenance()" >/dev/null
wait_worker_run 30 || true
out=$(psql_as regress_lock "$GOOD") || true
check_contains "verrou manuel conservé après un tour du worker" "locked" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_lock')" >/dev/null
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "unlock_role : connexion acceptée" "regress_lock" "$out"
wait_worker_run 30 || true
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "déverrouillage conservé après un tour du worker" "regress_lock" "$out"

# --- exempt_roles ---------------------------------------------------------------
psql_admin "CREATE ROLE regress_exempt LOGIN PASSWORD '$GOOD'"
psql_admin "ALTER SYSTEM SET pg_pass_policy.exempt_roles = 'regress_exempt'"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
for i in 1 2 3 4 5 6 7; do psql_as regress_exempt "$BAD" >/dev/null || true; done
out=$(psql_as regress_exempt "$GOOD" "SELECT current_user") || true
check_eq "rôle exempté : jamais verrouillé" "regress_exempt" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_exempt' AND locked_until IS NOT NULL")
check_eq "rôle exempté : aucun verrou en shmem" "0" "$out"

# --- rôle inexistant : pas de plantage ---------------------------------------
for i in 1 2 3 4 5 6; do psql_as regress_nobody "$BAD" >/dev/null || true; done
out=$(psql_admin "SELECT 1")
check_eq "le serveur répond après des échecs sur un rôle inexistant" "1" "$out"

ppp_finish

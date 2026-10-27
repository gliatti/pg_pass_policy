#!/usr/bin/env bash
# lockout.sh — verrouillage après N échecs d'authentification (SPEC §6.3, §7, §11)
#
# Vraies connexions TCP en SCRAM. Le mauvais mot de passe est toujours fourni
# explicitement (PGPASSWORD) : une connexion abandonnée avant l'envoi du mot
# de passe (STATUS_EOF) n'est pas comptée (SPEC §11).
#
# fsync = on (common.sh le force à off) : le signal de rechargement est envoyé
# au worker à la validation de la transaction appelante ; avec fsync = off la
# fenêtre entre l'envoi du signal et la visibilité du COMMIT serait masquée.
set -euo pipefail
. "$(dirname "$0")/common.sh"

GOOD='Lockout-Good#2024'
BAD='Lockout-Wrong#2024'

ppp_start "fsync = on"

# Attend un rechargement de la shmem postérieur à t0
wait_reload() {
	wait_for 30 "SELECT coalesce(max(last_reload) > '$1'::timestamptz, false) FROM pass_policy.worker_status()"
}

psql_admin "SELECT pass_policy.create_profile('p_lock',
  '{\"max_failures\": 5, \"failure_window\": \"1 minute\", \"lock_duration\": \"5 seconds\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_lock LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_lock', 'p_lock')" >/dev/null
if wait_reload "$t0"; then
	ok "le worker recharge les paramètres après assign_profile"
else
	fail "le worker n'a pas rechargé les paramètres (worker_status.last_reload)"
fi

out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "connexion initiale avec le bon mot de passe" "regress_lock" "$out"

# --- les paramètres rechargés sont bien les nouveaux (pas seulement last_reload) --
# max_failures = 2 au lieu de 5 par défaut : 2 échecs suffisent si le worker a
# lu la ligne role_profile validée par assign_profile, et non l'état antérieur.
psql_admin "SELECT pass_policy.create_profile('p_lock2',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": \"3 seconds\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_lock2 LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_lock2', 'p_lock2')" >/dev/null
wait_reload "$t0" || fail "pas de rechargement après assign_profile (regress_lock2)"
for i in 1 2; do psql_as regress_lock2 "$BAD" >/dev/null || true; done
out=$(psql_as regress_lock2 "$GOOD") || true
check_contains "profil max_failures = 2 appliqué dès le rechargement : verrouillé après 2 échecs" "locked" "$out"
sleep 4
out=$(psql_as regress_lock2 "$GOOD" "SELECT current_user") || true
check_eq "regress_lock2 : verrou de 3 s expiré" "regress_lock2" "$out"

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
# role_state porte le verrou (ou l'a déjà porté : run_maintenance() le lève,
# avec un audit role_unlocked « auto », dès que locked_until est passé)
out=$(psql_admin "SELECT coalesce((SELECT s.locked_by = 'auto' AND s.locked_until IS NOT NULL
                                    FROM pass_policy.role_state s WHERE s.role_name = 'regress_lock'), false)
                      OR EXISTS (SELECT FROM pass_policy.audit_log l WHERE l.event_type = 'role_unlocked'
                                    AND l.role_name = 'regress_lock' AND l.details->>'by' = 'auto')")
check_eq "verrou automatique copié dans role_state" "t" "$out"

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

# --- verrou expiré avant le passage du worker ---------------------------------
# worker_interval = 60 : le worker ne passe pas entre le verrou et son expiration.
# L'audit role_locked ne doit pas être perdu, et de nouveaux échecs après
# l'expiration doivent reverrouiller sans attendre le worker.
psql_admin "ALTER SYSTEM SET pg_pass_policy.worker_interval = 60"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 3  # le SIGHUP déclenche un dernier tour, puis le worker dort 60 s
n_locked_before=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_lock'")
for i in 1 2 3 4 5; do psql_as regress_lock "$BAD" >/dev/null || true; done
out=$(psql_as regress_lock "$GOOD") || true
check_contains "verrouillé (le worker dort)" "locked" "$out"
sleep 6
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "verrou expiré sans passage du worker : connexion acceptée" "regress_lock" "$out"
for i in 1 2 3 4 5; do psql_as regress_lock "$BAD" >/dev/null || true; done
out=$(psql_as regress_lock "$GOOD") || true
check_contains "5 nouveaux échecs après l'expiration : reverrouillé sans le worker" "locked" "$out"
sleep 6
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "second verrou expiré : connexion acceptée" "regress_lock" "$out"
# réveil du worker : run_maintenance() demande un rechargement (signal au COMMIT)
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT count(*) FROM pass_policy.run_maintenance()" >/dev/null
if wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()"; then
	ok "le worker endormi (60 s) est réveillé par le signal envoyé au COMMIT"
else
	fail "le worker ne s'est pas réveillé"
fi
n_locked_after=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_lock'")
check_eq "l'audit role_locked d'un verrou expiré avant le passage du worker est écrit" "1" "$( [ "$n_locked_after" -gt "$n_locked_before" ] && echo 1 || echo 0)"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock' AND locked_until IS NOT NULL")
check_eq "plus de verrou en shmem après le passage du worker" "0" "$out"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.worker_interval"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1

# --- fenêtre d'échecs (failure_window) ---------------------------------------
psql_admin "SELECT pass_policy.alter_profile('p_lock', '{\"failure_window\": \"2 seconds\"}')" >/dev/null
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
wait_reload "$t0" || true
for i in 1 2 3 4; do psql_as regress_lock "$BAD" >/dev/null || true; done
sleep 3
for i in 1 2 3 4; do psql_as regress_lock "$BAD" >/dev/null || true; done
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "4 + 4 échecs séparés de plus que failure_window : pas de verrou" "regress_lock" "$out"

# --- durées extrêmes : lock_duration de 100 ans et NULL ----------------------
# extract(epoch) dépasse int4 au-delà de 68 ans : le rechargement doit survivre.
psql_admin "SELECT pass_policy.create_profile('p_long',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": \"100 years\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_long LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_long', 'p_long')" >/dev/null
if wait_reload "$t0"; then
	ok "rechargement réussi avec lock_duration = 100 years"
else
	fail "pas de rechargement avec lock_duration = 100 years"
fi
n=$(grep -c 'integer out of range' "$PPP_TMP/server.log" || true)
check_eq "aucune erreur « integer out of range » dans le log" "0" "$n"
for i in 1 2; do psql_as regress_long "$BAD" >/dev/null || true; done
out=$(psql_admin "SELECT locked_until > now() + interval '60 years' FROM pass_policy.failed_attempts() WHERE role_name = 'regress_long'")
check_eq "verrou de (presque) 100 ans posé" "t" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_long')" >/dev/null

psql_admin "SELECT pass_policy.create_profile('p_manual',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": null, \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_manual LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_manual', 'p_manual')" >/dev/null
wait_reload "$t0" || fail "pas de rechargement (p_manual)"
for i in 1 2; do psql_as regress_manual "$BAD" >/dev/null || true; done
out=$(psql_admin "SELECT locked_until::text FROM pass_policy.failed_attempts() WHERE role_name = 'regress_manual'")
check_eq "lock_duration NULL : verrou jusqu'au déverrouillage manuel (infinity)" "infinity" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_manual')" >/dev/null
out=$(psql_as regress_manual "$GOOD" "SELECT current_user") || true
check_eq "regress_manual déverrouillé" "regress_manual" "$out"

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

# --- la shmem suit la transaction : ROLLBACK, SAVEPOINT -----------------------
out=$(printf '%s\n' "BEGIN;" "SELECT pass_policy.lock_role('regress_lock', NULL, 'rollback');" "ROLLBACK;" | psql_admin_script) || true
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "BEGIN / lock_role / ROLLBACK : connexion acceptée (shmem non modifiée)" "regress_lock" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock' AND locked_until IS NOT NULL")
check_eq "aucun verrou en shmem après ROLLBACK" "0" "$out"
out=$(printf '%s\n' "BEGIN;" "SAVEPOINT s;" "SELECT pass_policy.lock_role('regress_lock', NULL, 'savepoint');" "ROLLBACK TO SAVEPOINT s;" "COMMIT;" | psql_admin_script) || true
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "SAVEPOINT / lock_role / ROLLBACK TO / COMMIT : connexion acceptée" "regress_lock" "$out"
out=$(printf '%s\n' "BEGIN;" "SELECT pass_policy.lock_role('regress_lock', NULL, 'commit');" "COMMIT;" | psql_admin_script) || true
out=$(psql_as regress_lock "$GOOD") || true
check_contains "BEGIN / lock_role / COMMIT : verrou appliqué au COMMIT" "locked" "$out"
out=$(printf '%s\n' "BEGIN;" "SELECT pass_policy.unlock_role('regress_lock');" "ROLLBACK;" | psql_admin_script) || true
out=$(psql_as regress_lock "$GOOD") || true
check_contains "unlock_role annulé par ROLLBACK : toujours verrouillé" "locked" "$out"
out=$(printf '%s\n' "BEGIN;" "SAVEPOINT s;" "SELECT pass_policy.unlock_role('regress_lock');" "RELEASE SAVEPOINT s;" "COMMIT;" | psql_admin_script) || true
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "unlock_role dans un SAVEPOINT validé : déverrouillé au COMMIT" "regress_lock" "$out"

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

# --- aucun WARNING du worker pendant le test ---------------------------------
n=$(grep -c 'pg_pass_policy: worker .* failed' "$PPP_TMP/server.log" || true)
check_eq "aucun échec de cycle du worker dans le log" "0" "$n"

# --- bibliothèque retirée de shared_preload_libraries : lock_role échoue -----
# Sans préchargement, shmem_lock_role() ne peut pas écrire en mémoire partagée
# (le chargement de la bibliothèque échoue) : lock_role() et unlock_role()
# doivent échouer et annuler leur transaction, et non valider role_state et
# l'audit avec un simple WARNING (fail-open). Impossible en pg_regress, dont
# l'instance précharge toujours la bibliothèque.
echo "shared_preload_libraries = ''" >>"$PPP_TMP/data/postgresql.conf"
"$PPP_BINDIR/pg_ctl" -D "$PPP_TMP/data" -l "$PPP_TMP/server.log" -o "-p $PPP_PORT" -w -t 60 restart >/dev/null
audit0=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE role_name = 'regress_lock'")
out=$(psql_admin "SELECT pass_policy.lock_role('regress_lock', NULL, 'no preload')" 2>&1) && rc=0 || rc=$?
check_eq "sans préchargement : lock_role échoue" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "sans préchargement : ERROR explicite" "ERROR: .*shared_preload_libraries" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_state WHERE role_name = 'regress_lock' AND locked_until IS NOT NULL")
check_eq "sans préchargement : role_state non verrouillé (transaction annulée)" "0" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE role_name = 'regress_lock'")
check_eq "sans préchargement : aucun audit role_locked" "$audit0" "$out"
out=$(psql_admin "SELECT pass_policy.unlock_role('regress_lock')" 2>&1) && rc=0 || rc=$?
check_eq "sans préchargement : unlock_role échoue aussi" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"

ppp_finish

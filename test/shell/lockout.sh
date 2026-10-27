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

# --- run_maintenance() ne lève pas un verrou automatique plus récent ----------
# (revue finale 2, F4) role_state porte un verrou automatique expiré ; avant la
# maintenance suivante, 5 nouveaux échecs posent un nouveau verrou automatique
# que role_state ne connaît pas encore (le worker dort). L'étape f de
# run_maintenance() lève le verrou expiré de role_state, mais pas, en shmem,
# le verrou actif (shmem_unlock_role(…, expired_only => true)).
psql_admin "SELECT pass_policy.alter_profile('p_lock', '{\"failure_window\": \"1 minute\", \"lock_duration\": \"6 seconds\"}')" >/dev/null
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
wait_reload "$t0" || fail "F4 : pas de rechargement après alter_profile"
for i in 1 2 3 4 5; do psql_as regress_lock "$BAD" >/dev/null || true; done
if wait_for 30 "SELECT coalesce((SELECT locked_until > now() FROM pass_policy.role_state WHERE role_name = 'regress_lock'), false)"; then
	ok "F4 : premier verrou automatique copié dans role_state"
else
	fail "F4 : premier verrou automatique absent de role_state"
fi
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "ALTER SYSTEM SET pg_pass_policy.worker_interval = 600"
psql_admin "SELECT pg_reload_conf()" >/dev/null
wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || fail "F4 : pas de tour du worker après le passage à 600 s"
sleep 7 # le premier verrou expire ; role_state le porte encore (le worker dort)
out=$(psql_admin "SELECT locked_until < now() FROM pass_policy.role_state WHERE role_name = 'regress_lock'")
check_eq "F4 : role_state porte un verrou expiré" "t" "$out"
for i in 1 2 3 4 5; do psql_as regress_lock "$BAD" >/dev/null || true; done
out=$(psql_admin "SELECT action FROM pass_policy.run_maintenance() WHERE role_name = 'regress_lock'")
check_contains "F4 : run_maintenance() lève le verrou expiré de role_state" "role_unlocked" "$out"
out=$(psql_as regress_lock "$GOOD") || true
check_contains "F4 : le nouveau verrou automatique survit à run_maintenance()" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT locked_until > now() FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock'")
check_eq "F4 : verrou actif en shmem après la maintenance" "t" "$out"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.worker_interval"
psql_admin "SELECT pg_reload_conf()" >/dev/null
if wait_for 30 "SELECT coalesce((SELECT locked_until > now() FROM pass_policy.role_state WHERE role_name = 'regress_lock'), false)"; then
	ok "F4 : le nouveau verrou est copié dans role_state par le worker"
else
	fail "F4 : le nouveau verrou n'a pas été copié dans role_state"
fi
psql_admin "SELECT pass_policy.unlock_role('regress_lock')" >/dev/null
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "F4 : unlock_role() lève le nouveau verrou" "regress_lock" "$out"

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

# --- noms inexistants : une seule ligne d'audit agrégée par tour -------------
# (revue finale 2, F5) le worker dort (600 s) ; les échecs de regress_nobody
# ci-dessus sont d'abord journalisés par le tour du SIGHUP, puis 3 noms
# inexistants × 2 échecs, puis un seul tour (réveil par run_maintenance()).
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "ALTER SYSTEM SET pg_pass_policy.worker_interval = 600"
psql_admin "SELECT pg_reload_conf()" >/dev/null
wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || fail "F5 : pas de tour du worker après le passage à 600 s"
id0=$(psql_admin "SELECT coalesce(max(id), 0) FROM pass_policy.audit_log")
for n in regress_ghost_a regress_ghost_b regress_ghost_c; do
	for i in 1 2; do psql_as "$n" "$BAD" >/dev/null || true; done
done
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT count(*) FROM pass_policy.run_maintenance()" >/dev/null
wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || fail "F5 : pas de tour du worker après run_maintenance()"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE id > $id0 AND role_name LIKE 'regress_ghost%'")
check_eq "F5 : aucune ligne d'audit par nom inexistant" "0" "$out"
out=$(psql_admin "SELECT count(*) || ':' || string_agg((details->>'unknown_roles') || '/' || (details->>'attempts'), ',')
                    FROM pass_policy.audit_log WHERE id > $id0 AND event_type = 'auth_failed' AND role_name IS NULL")
check_eq "F5 : une seule ligne auth_failed agrégée (3 noms, 6 tentatives)" "1:3/6" "$out"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.worker_interval"
psql_admin "SELECT pg_reload_conf()" >/dev/null

# --- méthodes sans mot de passe : échecs non comptés -------------------------
# (revue finale 2, F1) seuls les échecs des méthodes qui vérifient un mot de
# passe ou un secret sont comptés. ident sans serveur identd (connexion
# refusée sur 127.0.0.1:113) échoue avec STATUS_ERROR sans que le client ait
# fourni de mot de passe : avant la correction, 6 échecs verrouillaient le
# rôle. Les lignes reject (par rôle, par base) n'atteignent pas le hook
# (FATAL dans ClientAuthentication() avant l'appel) : non comptées non plus.
psql_admin "CREATE ROLE regress_ident LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_rejected LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE DATABASE regress_rejectdb"
cp "$PPP_TMP/data/pg_hba.conf" "$PPP_TMP/pg_hba.conf.orig"
{
	echo "host all              regress_ident    127.0.0.1/32 ident"
	echo "host all              regress_rejected 127.0.0.1/32 reject"
	echo "host regress_rejectdb all              127.0.0.1/32 reject"
	cat "$PPP_TMP/pg_hba.conf.orig"
} >"$PPP_TMP/data/pg_hba.conf"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
n_lock0=$(psql_admin "SELECT coalesce((SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock'), 0)")
for i in 1 2 3 4 5 6; do
	out_ident=$(psql_as regress_ident "$BAD") || true
	out_rej=$(psql_as regress_rejected "$BAD") || true
	out_db=$(PGPASSWORD=$BAD "$PPP_BINDIR/psql" -X -q -At -w -h 127.0.0.1 -p "$PPP_PORT" \
		-U regress_lock -d regress_rejectdb -c "SELECT 1" 2>&1) || true
done
check_contains "F1 : ident refusé (aucun identd)" "Ident authentication failed" "$out_ident"
check_contains "F1 : ligne reject par rôle" "pg_hba.conf rejects connection" "$out_rej"
check_contains "F1 : ligne reject par base" "pg_hba.conf rejects connection.*regress_rejectdb" "$out_db"
check_not_contains "F1 : jamais « locked » pour une méthode sans mot de passe" "is locked by pg_pass_policy" "$out_ident$out_rej$out_db"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name IN ('regress_ident', 'regress_rejected')")
check_eq "F1 : failed_attempts() vide pour ident et reject" "0" "$out"
out=$(psql_admin "SELECT coalesce((SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_lock'), 0)")
check_eq "F1 : reject sur une base : compteur de regress_lock inchangé" "$n_lock0" "$out"
cp "$PPP_TMP/pg_hba.conf.orig" "$PPP_TMP/data/pg_hba.conf"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
out=$(psql_as regress_ident "$GOOD" "SELECT current_user") || true
check_eq "F1 : regress_ident non verrouillé (6 échecs ident)" "regress_ident" "$out"
out=$(psql_as regress_rejected "$GOOD" "SELECT current_user") || true
check_eq "F1 : regress_rejected non verrouillé (6 refus pg_hba)" "regress_rejected" "$out"

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

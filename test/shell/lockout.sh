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
                                    AND l.role_name = 'regress_lock' AND l.details->>'unlocked_by' = 'auto')")
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
# (clôture) shmem_unlock_role() renvoie alors false : l'étape f n'écrit pas
# d'audit role_unlocked et ne renvoie pas l'action (le rôle reste verrouillé).
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
n0=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_unlocked' AND role_name = 'regress_lock'")
out=$(psql_admin "SELECT count(*) FROM pass_policy.run_maintenance() WHERE role_name = 'regress_lock' AND action = 'role_unlocked'")
check_eq "F4 : run_maintenance() ne renvoie pas role_unlocked (déverrouillage refusé en shmem)" "0" "$out"
n1=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_unlocked' AND role_name = 'regress_lock'")
check_eq "F4 : aucun audit role_unlocked pour le déverrouillage refusé" "$n0" "$n1"
# le shmem_reload() de fin de passe réveille le worker, qui peut déjà avoir
# recopié le nouveau verrou : NULL ou verrou actif, jamais le verrou expiré
out=$(psql_admin "SELECT locked_until IS NULL OR locked_until > now() FROM pass_policy.role_state WHERE role_name = 'regress_lock'")
check_eq "F4 : le verrou expiré est effacé de role_state" "t" "$out"
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
psql_admin "ALTER SYSTEM SET pg_pass_policy.exempt_roles = 'regress_exempt, $PPP_SUPERUSER'"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
for i in 1 2 3 4 5 6 7; do psql_as regress_exempt "$BAD" >/dev/null || true; done
out=$(psql_as regress_exempt "$GOOD" "SELECT current_user") || true
check_eq "rôle exempté : jamais verrouillé" "regress_exempt" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_exempt' AND locked_until IS NOT NULL")
check_eq "rôle exempté : aucun verrou en shmem" "0" "$out"
# (clôture) liste découpée par le check hook (GUC extra) : nom entre guillemets
# (casse conservée), syntaxe invalide refusée sans toucher la valeur en place
psql_admin "CREATE ROLE \"Regress_Q\" LOGIN PASSWORD '$GOOD'"
out=$(psql_admin "ALTER SYSTEM SET pg_pass_policy.exempt_roles = 'regress_exempt,,x'" 2>&1) || true
check_contains "exempt_roles : liste invalide refusée par le check hook" "invalid value|List syntax" "$out"
psql_admin "ALTER SYSTEM SET pg_pass_policy.exempt_roles = 'regress_exempt, \"Regress_Q\", $PPP_SUPERUSER'"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
out=$(psql_admin "SELECT pass_policy._is_exempt('regress_exempt'), pass_policy._is_exempt('Regress_Q'), pass_policy._is_exempt('regress_q')")
check_eq "exempt_roles : noms simple et entre guillemets" "t|t|f" "$out"
# (clôture) rotate_password() d'un rôle exempté : le hook ne tourne pas,
# _ensure_recorded() enregistre le changement (_record_done() faux)
h0=$(psql_admin "SELECT count(*) FROM pass_policy.password_history WHERE role_name = 'regress_exempt'")
out=$(psql_admin "SELECT length(pass_policy.rotate_password('regress_exempt')) >= 24")
check_eq "rôle exempté : rotate_password() réussit" "t" "$out"
h1=$(psql_admin "SELECT count(*) FROM pass_policy.password_history WHERE role_name = 'regress_exempt'")
check_eq "rôle exempté : changement enregistré par _ensure_recorded()" "$((h0 + 1))" "$h1"
out=$(psql_admin "SELECT password_changed_at > now() - interval '1 minute' FROM pass_policy.role_state WHERE role_name = 'regress_exempt'")
check_eq "rôle exempté : role_state mis à jour" "t" "$out"
psql_admin "ALTER ROLE regress_exempt PASSWORD '$GOOD'" # utilisé plus loin

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
# (revue finale 4, H7) le worker dort : une demande shmem_reload() annulée par
# ROLLBACK TO SAVEPOINT ne le réveille pas ; validée par RELEASE, si.
t0=$(psql_admin "SELECT clock_timestamp()")
printf '%s\n' "BEGIN;" "SAVEPOINT s;" "SELECT pass_policy.shmem_reload();" "ROLLBACK TO SAVEPOINT s;" "COMMIT;" | psql_admin_script >/dev/null || true
sleep 3
out=$(psql_admin "SELECT coalesce(max(last_reload) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()")
check_eq "H7 : shmem_reload() annulé par ROLLBACK TO SAVEPOINT : worker non réveillé" "f" "$out"
t0=$(psql_admin "SELECT clock_timestamp()")
printf '%s\n' "BEGIN;" "SAVEPOINT s;" "SELECT pass_policy.shmem_reload();" "RELEASE SAVEPOINT s;" "COMMIT;" | psql_admin_script >/dev/null || true
if wait_for 30 "SELECT coalesce(max(last_reload) > '$t0'::timestamptz AND max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()"; then
	ok "H7 : shmem_reload() dans un SAVEPOINT validé : worker réveillé au COMMIT"
else
	fail "H7 : shmem_reload() dans un SAVEPOINT validé n'a pas réveillé le worker"
fi
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
# (vérification 6) failed_attempts() : les noms inexistants (champ utilisateur
# saisi par le client, peut-être un mot de passe) ne sont lus par leur nom que
# par un superutilisateur ; pass_policy_viewer en reçoit une seule ligne
# agrégée, role_name NULL
psql_admin "CREATE ROLE regress_fa_viewer LOGIN PASSWORD '$GOOD' IN ROLE pass_policy_viewer" >/dev/null
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name LIKE 'regress_ghost%'")
check_eq "failed_attempts() superutilisateur : noms inexistants visibles" "3" "$out"
out=$(psql_as regress_fa_viewer "$GOOD" "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name LIKE 'regress_ghost%' OR role_name = 'regress_nobody'")
check_eq "failed_attempts() viewer : aucun nom inexistant" "0" "$out"
out=$(psql_as regress_fa_viewer "$GOOD" "SELECT count(*), bool_and(failed_count >= 6) FROM pass_policy.failed_attempts() WHERE role_name IS NULL")
check_eq "failed_attempts() viewer : une ligne agrégée (role_name NULL, compteurs sommés)" "1|t" "$out"
out=$(psql_as regress_fa_viewer "$GOOD" "SELECT count(*) FROM pass_policy.v_role_status WHERE role_name IS NULL")
check_eq "failed_attempts() viewer : la ligne agrégée ne rejoint aucun rôle de v_role_status" "0" "$out"
# (vérification 7) l'existence du nom est décidée à la lecture (recherche
# syscache), pas par le drapeau role_missing en cache, rafraîchi seulement
# par une tentative : nom inexistant verrouillé (5 échecs, profil par
# défaut), puis CREATE ROLE, RENAME, CREATE ROLE à nouveau sous ce nom
fa_named() {
	psql_as regress_fa_viewer "$GOOD" "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_fa_rec' AND locked_until IS NOT NULL"
}
for i in 1 2 3 4 5; do psql_as regress_fa_rec "$BAD" >/dev/null || true; done
check_eq "failed_attempts() viewer : verrou d'un nom inexistant non nommé" "0" "$(fa_named)"
psql_admin "CREATE ROLE regress_fa_rec LOGIN" >/dev/null
check_eq "failed_attempts() viewer : rôle créé sous ce nom, verrou visible par son nom" "1" "$(fa_named)"
psql_admin "ALTER ROLE regress_fa_rec RENAME TO regress_fa_rec2" >/dev/null
check_eq "failed_attempts() viewer : rôle renommé, l'ancien nom n'est plus nommé" "0" "$(fa_named)"
psql_admin "CREATE ROLE regress_fa_rec LOGIN" >/dev/null
check_eq "failed_attempts() viewer : nom recréé, verrou visible par son nom" "1" "$(fa_named)"
psql_admin "SELECT pass_policy.shmem_unlock_role('regress_fa_rec')" >/dev/null
psql_admin "SELECT pass_policy.shmem_reset_failures('regress_fa_rec')" >/dev/null
psql_admin "DROP ROLE regress_fa_rec; DROP ROLE regress_fa_rec2" >/dev/null
psql_admin "DROP ROLE regress_fa_viewer" >/dev/null
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

# --- unlock_role() d'un verrou automatique sans ligne role_state ------------
# (revue finale 5, K1) le worker dort ; un verrou automatique attend son audit
# et le rôle n'a pas de ligne role_state. unlock_role() doit créer (et
# verrouiller) cette ligne comme lock_role() : sinon son UPDATE ne prend aucun
# verrou de ligne et l'upsert concurrent du worker peut valider le verrou
# périmé après le déverrouillage, que le rechargement suivant réinjecte. La
# course elle-même n'est pas reproductible à coup sûr : on vérifie la ligne
# créée par unlock_role() et l'état après le tour du worker.
psql_admin "SELECT pass_policy.create_profile('p_k1',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": \"1 hour\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "SELECT pass_policy.create_profile('p_k2',
  '{\"max_failures\": 2, \"failure_window\": \"1 minute\", \"lock_duration\": \"6 seconds\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_k1 LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_k2 LOGIN PASSWORD '$GOOD'"
psql_admin "CREATE ROLE regress_k3 LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_k1', 'p_k1'), pass_policy.assign_profile('regress_k2', 'p_k2'),
                   pass_policy.assign_profile('regress_k3', 'p_k2')" >/dev/null
wait_reload "$t0" || fail "K1 : pas de rechargement après assign_profile"
# K2 : premier verrou de regress_k2, journalisé et copié dans role_state
for i in 1 2; do psql_as regress_k2 "$BAD" >/dev/null || true; done
if wait_for 30 "SELECT coalesce((SELECT locked_until IS NOT NULL FROM pass_policy.role_state WHERE role_name = 'regress_k2'), false)"; then
	ok "K2 : premier verrou automatique copié dans role_state"
else
	fail "K2 : premier verrou automatique absent de role_state"
fi
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "ALTER SYSTEM SET pg_pass_policy.worker_interval = 600"
psql_admin "SELECT pg_reload_conf()" >/dev/null
wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || fail "K1 : pas de tour du worker après le passage à 600 s"
psql_admin "DELETE FROM pass_policy.role_state WHERE role_name = 'regress_k1'"
for i in 1 2; do psql_as regress_k1 "$BAD" >/dev/null || true; done
out=$(psql_as regress_k1 "$GOOD") || true
check_contains "K1 : verrou automatique posé (le worker dort)" "is locked by pg_pass_policy" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_k1')" >/dev/null
out=$(psql_admin "SELECT count(*) || ':' || bool_and(locked_until IS NULL) FROM pass_policy.role_state WHERE role_name = 'regress_k1'")
check_eq "K1 : unlock_role() crée la ligne role_state (non verrouillée)" "1:true" "$out"
out=$(psql_as regress_k1 "$GOOD" "SELECT current_user") || true
check_eq "K1 : déverrouillé avant le passage du worker" "regress_k1" "$out"

# --- étape f de run_maintenance() et verrou expiré en attente d'audit -------
# (revue finale 5, K2) role_state porte le premier verrou de regress_k2,
# expiré ; un second verrou automatique, posé et expiré pendant que le worker
# dort, attend son audit. L'étape f (shmem_unlock_role(…, expired_only))
# ne doit pas effacer locked_until de ce second verrou : le worker l'audite
# (sans lifted_before_audit) puis l'efface.
sleep 7
for i in 1 2; do psql_as regress_k2 "$BAD" >/dev/null || true; done
out=$(psql_as regress_k2 "$GOOD") || true
check_contains "K2 : second verrou automatique posé (le worker dort)" "is locked by pg_pass_policy" "$out"
sleep 7
out=$(psql_admin "SELECT locked_until < now() FROM pass_policy.role_state WHERE role_name = 'regress_k2'")
check_eq "K2 : role_state porte le premier verrou, expiré" "t" "$out"
# failed_attempts() ne montre pas un verrou expiré : l'effet de l'étape f se
# lit dans la ligne role_locked que le worker écrira (lifted_before_audit).
psql_admin "SELECT pass_policy._shmem('unlock_expired', 'regress_k2')" >/dev/null
out=$(psql_as regress_k2 "$GOOD" "SELECT current_user") || true
check_eq "K2 : le verrou expiré ne bloque pas" "regress_k2" "$out"
n_k2=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_k2'")
check_eq "K2 : un seul role_locked avant le passage du worker" "1" "$n_k2"

# Les deux tours suivants (K1, K2) : run_maintenance() lève le verrou expiré
# de role_state et réveille le worker au COMMIT.
t0=$(psql_admin "SELECT clock_timestamp()")
out=$(psql_admin "SELECT string_agg(action, ',') FROM pass_policy.run_maintenance() WHERE role_name = 'regress_k2'")
check_contains "K2 : run_maintenance() lève le premier verrou de role_state" "role_unlocked" "$out"
wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || fail "K1/K2 : pas de tour du worker après run_maintenance()"
out=$(psql_as regress_k1 "$GOOD" "SELECT current_user") || true
check_eq "K1 : toujours déverrouillé après le tour du worker" "regress_k1" "$out"
out=$(psql_admin "SELECT count(*) || ':' || bool_and(locked_until IS NULL) FROM pass_policy.role_state WHERE role_name = 'regress_k1'")
check_eq "K1 : role_state reste non verrouillé après le tour du worker" "1:true" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_k1' AND locked_until IS NOT NULL")
check_eq "K1 : aucun verrou réinjecté en mémoire partagée" "0" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_k1'
                     AND (details->>'lifted_before_audit')::boolean")
check_eq "K1 : verrou automatique audité, levé avant l'audit" "1" "$out"
out=$(psql_admin "SELECT coalesce(details->>'lifted_before_audit', 'absent') FROM pass_policy.audit_log
                   WHERE event_type = 'role_locked' AND role_name = 'regress_k2' ORDER BY id DESC LIMIT 1")
check_eq "K2 : second verrou audité sans lifted_before_audit" "absent" "$out"
n=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_k2'")
check_eq "K2 : deux role_locked (un par verrou)" "2" "$n"
out=$(psql_admin "SELECT locked_until < now() FROM pass_policy.role_state WHERE role_name = 'regress_k2'")
check_eq "K2 : le second verrou (expiré) est copié dans role_state" "t" "$out"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT count(*) FROM pass_policy.run_maintenance()" >/dev/null
out=$(psql_admin "SELECT locked_until IS NULL FROM pass_policy.role_state WHERE role_name = 'regress_k2'")
check_eq "K2 : role_state cohérent (verrou expiré levé)" "t" "$out"
wait_for 30 "SELECT coalesce(max(last_run) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()" || true

# --- enabled = off : le worker ne modifie rien ------------------------------
# (revue finale 5, K3) un échec de regress_k3 attend son audit ; pendant que
# pg_pass_policy.enabled = off, ni le tour du SIGHUP ni un shmem_reload()
# n'écrivent l'audit (worker suspendu) ; il l'est au retour à on.
psql_as regress_k3 "$BAD" >/dev/null || true
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "ALTER SYSTEM SET pg_pass_policy.enabled = off"
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 2
psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
sleep 3
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE role_name = 'regress_k3' AND event_type = 'auth_failed'")
check_eq "K3 : enabled = off : aucun audit écrit par le worker" "0" "$out"
out=$(psql_admin "SELECT coalesce(max(last_run) > '$t0'::timestamptz OR max(last_reload) > '$t0'::timestamptz, false) FROM pass_policy.worker_status()")
check_eq "K3 : enabled = off : ni tour ni rechargement" "f" "$out"
n=$(grep -c 'worker suspended: pg_pass_policy.enabled is off' "$PPP_TMP/server.log" || true)
check_eq "K3 : LOG « worker suspended » écrit une fois" "1" "$n"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.enabled"
psql_admin "SELECT pg_reload_conf()" >/dev/null
if wait_for 30 "SELECT count(*) = 1 FROM pass_policy.audit_log WHERE role_name = 'regress_k3' AND event_type = 'auth_failed'"; then
	ok "K3 : retour à on : l'échec en attente est journalisé"
else
	fail "K3 : l'échec en attente n'a pas été journalisé après le retour à on"
fi
n=$(grep -c 'worker resumed: pg_pass_policy.enabled is on' "$PPP_TMP/server.log" || true)
check_eq "K3 : LOG « worker resumed »" "1" "$n"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.worker_interval"
psql_admin "SELECT pg_reload_conf()" >/dev/null

# --- aucun WARNING du worker pendant le test ---------------------------------
n=$(grep -c 'pg_pass_policy: worker .* failed' "$PPP_TMP/server.log" || true)
check_eq "aucun échec de cycle du worker dans le log" "0" "$n"

# --- lock_role() concurrent de l'écriture d'un verrou automatique -----------
# Un verrou automatique attend son audit pendant qu'une transaction de
# lock_role() tient la ligne role_state : l'upsert du worker attend ce verrou
# de ligne puis écrirait par-dessus le verrou manuel validé entre-temps, et le
# rechargement du même tour le recopierait en mémoire partagée (le verrou
# manuel « infinity » deviendrait un verrou auto qui expire). Le worker
# compare lock_seq avant son COMMIT et recommence au tour suivant.
psql_admin "SELECT pass_policy.create_profile('p_race',
  '{\"max_failures\": 3, \"failure_window\": \"1 minute\", \"lock_duration\": \"1 hour\", \"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_race LOGIN PASSWORD '$GOOD'"
t0=$(psql_admin "SELECT clock_timestamp()")
psql_admin "SELECT pass_policy.assign_profile('regress_race', 'p_race')" >/dev/null
wait_reload "$t0" || fail "pas de rechargement après assign_profile (regress_race)"
race_out="$PPP_TMP/race_lock.out"
printf '%s\n' "BEGIN;" "SELECT pass_policy.lock_role('regress_race', NULL, 'race') IS NOT NULL;" \
	"SELECT pg_sleep(6);" "COMMIT;" | psql_admin_script >"$race_out" &
race_pid=$!
sleep 1
for i in 1 2 3; do psql_as regress_race "$BAD" >/dev/null || true; done
out=$(psql_admin "SELECT locked_until > now() + interval '50 minutes' AND locked_until <> 'infinity' FROM pass_policy.failed_attempts() WHERE role_name = 'regress_race'")
check_eq "verrou automatique posé pendant la transaction de lock_role()" "t" "$out"
wait "$race_pid" || fail "transaction lock_role() en échec" "$(cat "$race_out")"
wait_worker_run 30 || true
wait_worker_run 30 || true
out=$(psql_admin "SELECT locked_by, locked_until = 'infinity' FROM pass_policy.role_state WHERE role_name = 'regress_race'")
check_eq "role_state : le verrou manuel validé n'est pas écrasé par le verrou auto" "manual|t" "$out"
out=$(psql_admin "SELECT locked_by, locked_until = 'infinity' FROM pass_policy.v_locked WHERE role_name = 'regress_race'")
check_eq "v_locked : manual / infinity après deux tours" "manual|t" "$out"
out=$(psql_admin "SELECT locked_until = 'infinity' FROM pass_policy.failed_attempts() WHERE role_name = 'regress_race'")
check_eq "mémoire partagée : verrou manuel conservé" "t" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_race' AND details->>'locked_by' = 'auto'")
check_eq "verrou automatique audité une fois" "1" "$out"
n=$(grep -c 'lock of role "regress_race" changed while its automatic lock was being written' "$PPP_TMP/server.log" || true)
log "info : $n tour(s) du worker annulé(s) par la vérification de lock_seq"
psql_admin "SELECT pass_policy.unlock_role('regress_race')" >/dev/null

# --- démarrage : fenêtre fail-closed (SPEC §6.3 « Démarrage », revue finale 6) --
# Après un démarrage, le hash est vide tant que le worker n'a pas réinjecté
# les verrous de role_state. Un rôle verrouillé à la main (verrou « infinity »
# d'un compte compromis) ne doit jamais entrer pendant cette fenêtre : refus
# « locked » si le verrou est déjà réinjecté, 57P03 sinon. worker_interval = 0
# vérifie au passage que le worker fait quand même un premier rechargement.
restart_server() {
	"$PPP_BINDIR/pg_ctl" -D "$PPP_TMP/data" -l "$PPP_TMP/server.log" -o "-p $PPP_PORT" -w -t 60 restart >/dev/null
}
psql_admin "SELECT pass_policy.lock_role('regress_lock', NULL, 'compromised')" >/dev/null
psql_admin "ALTER SYSTEM SET pg_pass_policy.worker_interval = 0" >/dev/null
restart_server
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_not_contains "démarrage : connexion immédiate du rôle verrouillé jamais acceptée" "^regress_lock$" "$out"
check_contains "démarrage : refus immédiat (locked ou lock state not loaded)" "is locked by pg_pass_policy|lock state not loaded yet" "$out"
if wait_for 30 "SELECT last_reload IS NOT NULL FROM pass_policy.worker_status()"; then
	ok "worker_interval = 0 : premier rechargement fait au démarrage"
else
	fail "worker_interval = 0 : aucun rechargement au démarrage"
fi
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_contains "démarrage : après le premier tour, refus « locked »" "is locked by pg_pass_policy" "$out"
out=$(psql_as regress_exempt "$GOOD" "SELECT current_user") || true
check_eq "démarrage : le rôle exempté se connecte" "regress_exempt" "$out"

# --- (vérification) worker_interval = 0 : rechargement sans run_maintenance() --
# Le worker ne tourne que sur demande (shmem_reload) et ne lance jamais
# run_maintenance() : une ligne role_profile d'un rôle supprimé n'est pas
# purgée. Le rechargement ne doit pas en tirer une entrée « profil » (KEEP,
# jamais évincée) pour l'ancien nom : elle redevient ordinaire, puis est purgée.
reload_sync() {
	local t
	t=$(psql_admin "SELECT clock_timestamp()")
	psql_admin "SELECT pass_policy.shmem_reload()" >/dev/null
	wait_reload "$t"
}
n_tracked() { psql_admin "SELECT tracked_roles FROM pass_policy.worker_status()"; }
reload_sync || fail "pas de rechargement (worker_interval = 0)"
reload_sync || true
n0=$(n_tracked)
psql_admin "CREATE ROLE regress_orphan LOGIN" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_orphan', 'p_lock')" >/dev/null
reload_sync || fail "pas de rechargement après assign_profile(regress_orphan)"
check_eq "profil assigné : une entrée de plus en mémoire partagée" "$((n0 + 1))" "$(n_tracked)"
psql_admin "DROP ROLE regress_orphan" >/dev/null
reload_sync || true
reload_sync || true
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_profile WHERE role_name = 'regress_orphan'")
check_eq "rôle supprimé : ligne role_profile orpheline encore présente (pas de run_maintenance)" "1" "$out"
check_eq "rôle supprimé : plus aucune entrée profil pour lui après rechargement" "$n0" "$(n_tracked)"

# --- (vérification) verrou automatique puis ALTER ROLE ... RENAME (SPEC §12) --
# L'entrée de la mémoire partagée est indexée par le nom, role_state par l'OID.
# Renommé avant le passage du worker (worker_interval = 0 : il ne tourne que
# sur demande), le rôle n'a plus de ligne pg_roles sous l'ancien nom : l'audit
# role_locked est écrit sous l'ancien nom avec role_missing / role_renamed /
# renamed_to, une seule fois ; le verrou n'est pas recopié dans role_state,
# et il ne suit pas le rôle sous son nouveau nom (vérification 13 : seul un
# verrou persisté dans role_state le suit) ; il reste sous l'ancien nom
# (vérification 14 : aucun verrou perdu, voir regress_nr ci-dessous).
psql_admin "CREATE ROLE regress_ren LOGIN PASSWORD '$GOOD'" >/dev/null
# profil assigné : la ligne role_profile garde l'ancien nom, ce qui permet au
# worker de nommer le nouveau (renamed_to) ; sans elle ni ligne role_state,
# seul role_missing est écrit
psql_admin "SELECT pass_policy.assign_profile('regress_ren', 'p_lock')" >/dev/null
reload_sync || true	# tour éventuellement demandé par CREATE ROLE, terminé avant les échecs
for i in 1 2 3 4 5; do psql_as regress_ren "$BAD" >/dev/null || true; done
out=$(psql_as regress_ren "$GOOD") || true
check_contains "regress_ren verrouillé automatiquement (5 échecs)" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_ren'")
check_eq "verrou automatique pas encore audité (worker non réveillé)" "0" "$out"
psql_admin "ALTER ROLE regress_ren RENAME TO regress_ren2" >/dev/null
reload_sync || fail "pas de tour du worker après le renommage"
out=$(psql_admin "SELECT details->>'locked_by', details->>'role_missing', details->>'role_renamed', details->>'renamed_to'
                    FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_ren'")
check_eq "renommage : role_locked audité sous l'ancien nom (role_renamed, renamed_to)" "auto|true|true|regress_ren2" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_state s JOIN pg_roles r ON r.oid = s.role_oid
                   WHERE r.rolname = 'regress_ren2' AND s.locked_until IS NOT NULL")
check_eq "renommage : verrou non recopié dans role_state" "0" "$out"
reload_sync || true
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name IN ('regress_ren', 'regress_ren2')")
check_eq "renommage : acquitté, audité une seule fois (pas de réécriture à chaque tour)" "1" "$out"
# Une fois audité et acquitté, l'entrée n'est pas retirée : role_state n'a
# pas ce verrou, le rechargement ne pourrait pas le réinjecter (vérification 14)
n=$(grep -c 'lock of role "regress_ren" renamed to "regress_ren2"' "$PPP_TMP/server.log" || true)
check_eq "renommage : verrou non persisté, aucun LOG de retrait" "0" "$n"
out=$(psql_as regress_ren2 "$GOOD" "SELECT current_user") || true
check_eq "renommage : verrou non persisté, le nouveau nom repart de zéro" "regress_ren2" "$out"
psql_admin "DROP ROLE regress_ren2" >/dev/null

# --- (vérification 14) verrou non persisté, renommage : l'entrée reste ------
# Verrou automatique permanent (p_manual) posé puis rôle renommé avant
# l'audit : le worker ne le recopie pas dans role_state (rôle renommé). Une
# fois l'entrée réglée, le nettoyage ne la retire pas (aucune ligne
# role_state ne couvre ce verrou pour cet OID) : le verrou reste sous l'ancien
# nom, sans LOG de retrait. Avec 63a6575, l'entrée était retirée (LOG
# « renamed to ») et le verrou perdu.
psql_admin "CREATE ROLE regress_nr LOGIN PASSWORD '$GOOD'" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_nr', 'p_manual')" >/dev/null
reload_sync || true
for i in 1 2; do psql_as regress_nr "$BAD" >/dev/null || true; done
out=$(psql_as regress_nr "$GOOD") || true
check_contains "regress_nr verrouillé automatiquement (p_manual)" "is locked by pg_pass_policy" "$out"
psql_admin "ALTER ROLE regress_nr RENAME TO regress_nr2" >/dev/null 2>&1
reload_sync || fail "pas de tour du worker après le renommage de regress_nr"
reload_sync || true
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_nr'")
check_eq "verrou non persisté renommé : audité" "1" "$out"
n=$(grep -c 'lock of role "regress_nr" renamed to' "$PPP_TMP/server.log" || true)
check_eq "verrou non persisté renommé : aucun LOG de retrait" "0" "$n"
out=$(psql_admin "SELECT locked_until = 'infinity' FROM pass_policy.failed_attempts() WHERE role_name = 'regress_nr'")
check_eq "verrou non persisté renommé : verrou conservé sous l'ancien nom" "t" "$out"
psql_admin "SELECT pass_policy.shmem_unlock_role('regress_nr')" >/dev/null
psql_admin "DROP ROLE regress_nr2" >/dev/null

# --- (vérification 13) verrou automatique audité et persisté, puis renommage
# Le verrou (p_manual : jusqu'au déverrouillage manuel) est écrit dans
# role_state avant le renommage : le worker retire l'entrée de l'ancien nom
# (LOG) et le rechargement le réinjecte par OID sous le nouveau nom. Un rôle
# créé ensuite sous l'ancien nom se connecte : le hook ne lui applique pas le
# verrou d'un autre OID.
psql_admin "CREATE ROLE regress_mv LOGIN PASSWORD '$GOOD'" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_mv', 'p_manual')" >/dev/null
reload_sync || true
for i in 1 2; do psql_as regress_mv "$BAD" >/dev/null || true; done
reload_sync || fail "pas de tour du worker après le verrou de regress_mv"
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_state s JOIN pg_roles r ON r.oid = s.role_oid
                   WHERE r.rolname = 'regress_mv' AND s.locked_until = 'infinity' AND s.locked_by = 'auto'")
check_eq "verrou automatique audité : persisté dans role_state" "1" "$out"
psql_admin "ALTER ROLE regress_mv RENAME TO regress_mv2" >/dev/null 2>&1
GOOD_MV='Lockout-Renamed#2024'
psql_admin "CREATE ROLE regress_mv LOGIN PASSWORD '$GOOD_MV'" >/dev/null
reload_sync || fail "pas de tour du worker après le renommage de regress_mv"
n=$(grep -c 'lock of role "regress_mv" renamed to "regress_mv2": reloaded from role_state' "$PPP_TMP/server.log" || true)
check_eq "renommage d'un verrou persisté : LOG « renamed to »" "1" "$n"
out=$(psql_as regress_mv2 "$GOOD") || true
check_contains "renommage d'un verrou persisté : le nouveau nom reste verrouillé" "is locked by pg_pass_policy" "$out"
out=$(psql_as regress_mv "$GOOD_MV" "SELECT current_user") || true
check_eq "renommage d'un verrou persisté : le rôle recréé sous l'ancien nom se connecte" "regress_mv" "$out"
psql_admin "SELECT pass_policy.unlock_role('regress_mv2')" >/dev/null
psql_admin "DROP ROLE regress_mv; DROP ROLE regress_mv2" >/dev/null

# --- (vérification 13) entrée réglée d'un autre OID rencontrée par le hook
# Verrou posé par shmem_lock_role() (rien à auditer), DROP ROLE puis CREATE
# ROLE du même nom, connexion avant tout tour du worker : le verrou n'est pas
# celui du nouveau rôle, l'entrée repart de zéro et l'échec est compté.
psql_admin "CREATE ROLE regress_rs LOGIN PASSWORD '$GOOD'" >/dev/null
reload_sync || true
psql_admin "SELECT pass_policy.shmem_lock_role('regress_rs', NULL)" >/dev/null
out=$(psql_as regress_rs "$GOOD") || true
check_contains "regress_rs verrouillé en mémoire partagée" "is locked by pg_pass_policy" "$out"
GOOD_RS='Lockout-Restart#2024'
psql_admin "DROP ROLE regress_rs; CREATE ROLE regress_rs LOGIN PASSWORD '$GOOD_RS'" >/dev/null
psql_as regress_rs "$BAD" >/dev/null || true
out=$(psql_admin "SELECT failed_count, locked_until IS NULL FROM pass_policy.failed_attempts() WHERE role_name = 'regress_rs'")
check_eq "rôle recréé : entrée remise à zéro par le hook, échec compté" "1|t" "$out"
out=$(psql_as regress_rs "$GOOD_RS" "SELECT current_user") || true
check_eq "rôle recréé : connexion réussie" "regress_rs" "$out"
psql_admin "DROP ROLE regress_rs" >/dev/null

# --- (vérification 3) verrou automatique, DROP ROLE puis CREATE ROLE sous le
# même nom avant le passage du worker (SPEC §12) : le hook mémorise l'OID du
# rôle verrouillé, le worker ne recopie pas le verrou dans role_state pour le
# nouveau rôle (autre OID) ; l'audit dit role_missing et role_recreated, et
# l'entrée est retirée une fois le verrou audité. Avant ce tour du worker,
# l'audit de l'ancien rôle est en attente : la connexion du nouveau rôle est
# refusée comme verrouillée (vérification 14, fail-closed ; avec 63a6575 elle
# passait sans rien compter).
# DROP et CREATE dans une seule transaction : le worker ne peut pas passer
# entre les deux (il verrait seulement un rôle supprimé, cas déjà couvert).
psql_admin "CREATE ROLE regress_rec LOGIN PASSWORD '$GOOD'" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_rec', 'p_lock')" >/dev/null
reload_sync || true
for i in 1 2 3 4 5; do psql_as regress_rec "$BAD" >/dev/null || true; done
out=$(psql_as regress_rec "$GOOD") || true
check_contains "regress_rec verrouillé automatiquement (5 échecs)" "is locked by pg_pass_policy" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_rec'")
check_eq "rôle recréé : verrou automatique pas encore audité" "0" "$out"
# autre mot de passe : la ligne d'historique sans OID du CREATE ROLE de
# l'ancien rôle, pas encore rattachée (pas de run_maintenance()), vaut pour
# le nom (SPEC §11, C3)
GOOD_REC='Lockout-Recreated#2024'
psql_admin "DROP ROLE regress_rec; CREATE ROLE regress_rec LOGIN PASSWORD '$GOOD_REC'" >/dev/null
out=$(psql_as regress_rec "$GOOD_REC" "SELECT current_user") || true
check_contains "rôle recréé : refusé avant le tour du worker (audit de l'ancien rôle en attente)" "is locked by pg_pass_policy" "$out"
reload_sync || fail "pas de tour du worker après DROP ROLE / CREATE ROLE"
out=$(psql_admin "SELECT details->>'role_missing', details->>'role_recreated', coalesce(details->>'renamed_to', 'null')
                    FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_rec'")
check_eq "rôle recréé : role_locked audité avec role_missing et role_recreated" "true|true|null" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_state s JOIN pg_roles r ON r.oid = s.role_oid
                   WHERE r.rolname = 'regress_rec' AND s.locked_until IS NOT NULL")
check_eq "rôle recréé : le verrou de l'ancien rôle n'est pas recopié dans role_state" "0" "$out"
reload_sync || true
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'role_locked' AND role_name = 'regress_rec'")
check_eq "rôle recréé : acquitté, audité une seule fois" "1" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name = 'regress_rec' AND locked_until IS NOT NULL")
check_eq "rôle recréé : plus de verrou en mémoire partagée une fois audité" "0" "$out"
out=$(psql_admin "SELECT count(*) FROM pass_policy.role_state s JOIN pg_roles r ON r.oid = s.role_oid
                   WHERE r.rolname = 'regress_rec' AND s.locked_until IS NOT NULL")
check_eq "rôle recréé : toujours aucun verrou dans role_state" "0" "$out"
out=$(psql_as regress_rec "$GOOD_REC" "SELECT current_user") || true
check_eq "rôle recréé : le nouveau rôle se connecte" "regress_rec" "$out"
psql_admin "DROP ROLE regress_rec" >/dev/null

# --- (vérification 14) compteurs d'un rôle supprimé, rôle recréé -----------
# Quatre échecs audités (p_lock : 5 échecs), DROP ROLE + CREATE ROLE du même
# nom, un échec du nouveau rôle : l'entrée appartient à l'OID de l'ancien
# rôle (owner_oid), réglée, elle repart de zéro avant de compter. Avec
# 63a6575, le cinquième échec cumulé verrouillait le nouveau rôle.
psql_admin "CREATE ROLE regress_cnt LOGIN PASSWORD '$GOOD'" >/dev/null
psql_admin "SELECT pass_policy.assign_profile('regress_cnt', 'p_lock')" >/dev/null
reload_sync || true
for i in 1 2 3 4; do psql_as regress_cnt "$BAD" >/dev/null || true; done
reload_sync || fail "pas de tour du worker après les échecs de regress_cnt"
check_eq "regress_cnt : 4 échecs comptés" "4" \
	"$(psql_admin "SELECT failed_count FROM pass_policy.failed_attempts() WHERE role_name = 'regress_cnt'")"
GOOD_CNT='Lockout-Counter#2024'
psql_admin "DROP ROLE regress_cnt; CREATE ROLE regress_cnt LOGIN PASSWORD '$GOOD_CNT'" >/dev/null
psql_as regress_cnt "$BAD" >/dev/null || true
out=$(psql_admin "SELECT failed_count, locked_until IS NULL FROM pass_policy.failed_attempts() WHERE role_name = 'regress_cnt'")
check_eq "rôle recréé : compteurs de l'ancien rôle non hérités (1 échec, pas de verrou)" "1|t" "$out"
out=$(psql_as regress_cnt "$GOOD_CNT" "SELECT current_user") || true
check_eq "rôle recréé : connexion réussie (compteurs non hérités)" "regress_cnt" "$out"
# rechargement demandé par la remise à zéro (ppp_restart_entry) servi avant
# la suite : aucun tour du worker n'audite les échecs suivants
reload_sync || true
# Mêmes échecs, pas encore audités : la connexion du rôle recréé est refusée,
# bon mot de passe compris, jusqu'au tour du worker (fail-closed)
for i in 1 2 3 4; do psql_as regress_cnt "$BAD" >/dev/null || true; done
GOOD_CNT2='Lockout-Counter#2025'
psql_admin "DROP ROLE regress_cnt; CREATE ROLE regress_cnt LOGIN PASSWORD '$GOOD_CNT2'" >/dev/null
out=$(psql_as regress_cnt "$GOOD_CNT2" "SELECT current_user") || true
check_contains "rôle recréé, échecs de l'ancien en attente d'audit : refusé" "is locked by pg_pass_policy" "$out"
reload_sync || fail "pas de tour du worker après la recréation de regress_cnt"
out=$(psql_as regress_cnt "$GOOD_CNT2" "SELECT current_user") || true
check_eq "rôle recréé, échecs audités : connexion réussie" "regress_cnt" "$out"
psql_admin "DROP ROLE regress_cnt" >/dev/null

# Fenêtre tenue ouverte de façon déterministe : role_state renommée, le
# rechargement du worker échoue (WARNING) et la fenêtre reste fermée.
# worker_interval reste à 0 : le rechargement doit être retenté sans SIGHUP
# (revue finale 7, constat 1).
psql_admin "CREATE ROLE regress_su SUPERUSER LOGIN PASSWORD '$GOOD'" >/dev/null
# (vérification 6) rôle verrouillé dans role_state et authentifié par une
# méthode sans secret (trust) : refusé lui aussi pendant la fenêtre (57P03),
# puis « locked » une fois les verrous réinjectés
psql_admin "CREATE ROLE regress_trust_locked LOGIN" >/dev/null
psql_admin "SELECT pass_policy.lock_role('regress_trust_locked', NULL, 'trust test')" >/dev/null
# (vérification 7, restreinte en vérification 8) voie d'administration de
# secours : pendant la fenêtre, seul un superutilisateur listé dans
# pg_pass_policy.rescue_roles et authentifié en peer entre, sauf verrou en
# shmem ; rescue_roles vide (défaut) : aucun accès de secours. Un
# superutilisateur en trust local (même listé), en peer non listé, en trust
# TCP ou dont le contrôle peer échoue, un rôle ordinaire listé en peer ou en
# trust local reçoivent 57P03. Socket Unix ouverte pour la suite du script
# (dernière valeur de postgresql.conf).
psql_admin "CREATE ROLE regress_su_peer SUPERUSER LOGIN" >/dev/null
psql_admin "CREATE ROLE regress_su_peer2 SUPERUSER LOGIN" >/dev/null
psql_admin "CREATE ROLE regress_su_nopeer SUPERUSER LOGIN" >/dev/null
psql_admin "CREATE ROLE regress_su_tcp SUPERUSER LOGIN" >/dev/null
psql_admin "CREATE ROLE regress_su_unlisted SUPERUSER LOGIN" >/dev/null
psql_admin "CREATE ROLE regress_peer_plain LOGIN" >/dev/null
mkdir -p "$PPP_TMP/sock"
echo "unix_socket_directories = '$PPP_TMP/sock'" >>"$PPP_TMP/data/postgresql.conf"
{
	echo "pppmap $(id -un) regress_su_peer"
	echo "pppmap $(id -un) regress_su_peer2"
	echo "pppmap $(id -un) regress_su_unlisted"
	echo "pppmap $(id -un) regress_peer_plain"
} >>"$PPP_TMP/data/pg_ident.conf"
psql_local() {
	"$PPP_BINDIR/psql" -X -q -At -w -v ON_ERROR_STOP=1 \
		-h "$PPP_TMP/sock" -p "$PPP_PORT" -U "$1" -d "$PPP_DB" -c "${2:-SELECT current_user}" 2>&1
}
cp "$PPP_TMP/data/pg_hba.conf" "$PPP_TMP/pg_hba.conf.orig"
{
	echo "local all regress_su_peer peer map=pppmap"
	echo "local all regress_su_peer2 peer map=pppmap"
	echo "local all regress_su_unlisted peer map=pppmap"
	echo "local all regress_peer_plain peer map=pppmap"
	echo "local all regress_su_nopeer peer"
	echo "local all regress_su trust"
	echo "local all regress_window trust"
	echo "host all regress_su_tcp 127.0.0.1/32 trust"
	echo "host all regress_trust_locked 127.0.0.1/32 trust"
	cat "$PPP_TMP/pg_hba.conf.orig"
} >"$PPP_TMP/data/pg_hba.conf"
psql_admin "ALTER TABLE pass_policy.role_state RENAME TO role_state_hidden" >/dev/null
log0=$(wc -l <"$PPP_TMP/server.log")
restart_server
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_contains "fenêtre : bon mot de passe refusé (57P03 lock state not loaded yet)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
client_out="$out"
out=$(psql_as regress_lock "$BAD" "SELECT current_user") || true
check_contains "fenêtre : mauvais mot de passe, même réponse (pas d'oracle)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
client_out="$client_out$out"
# (vérification 10, (2-3)) refus générique : aucun HINT au client, ni sur la
# voie de secours ni sur le reste de la configuration ; l'information complète
# est dans le HINT du LOG serveur (vérifiée plus bas)
check_not_contains "fenêtre : le refus 57P03 ne porte aucun HINT" "HINT" "$out"
out=$(psql_as regress_trust_locked "" "SELECT current_user") || true
check_contains "fenêtre : rôle verrouillé par trust refusé aussi (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
psql_admin "CREATE ROLE regress_window LOGIN PASSWORD '$GOOD'" >/dev/null
# 4 mauvais + bon + mauvais : l'entrée n'est pas modifiée pendant la fenêtre
# (ni échec compté, ni remise à zéro par le succès), toujours 57P03
res=""
for pwd in "$BAD" "$BAD" "$BAD" "$BAD" "$GOOD" "$BAD"; do
	out=$(psql_as regress_window "$pwd" "SELECT current_user") || true
	if printf '%s' "$out" | grep -q 'lock state not loaded yet'; then res="${res}R"; else res="${res}?"; fi
done
check_eq "fenêtre : 4 mauvais + bon + mauvais, toujours 57P03 (jamais locked)" "RRRRRR" "$res"
out=$(psql_admin "SELECT count(*) FROM pass_policy.failed_attempts() WHERE role_name IN ('regress_window', 'regress_lock')")
check_eq "fenêtre : aucun échec compté (failed_attempts vide)" "0" "$out"
out=$(psql_as regress_window "$GOOD" "SELECT current_user") || true
check_contains "fenêtre : rôle non verrouillé et non exempté refusé aussi" "lock state not loaded yet" "$out"
out=$(psql_as regress_exempt "$GOOD" "SELECT current_user") || true
check_eq "fenêtre : le rôle exempté se connecte" "regress_exempt" "$out"
# Worker présent (rechargement en échec) : un superutilisateur non exempté est
# refusé comme les autres (revue finale 8, constat 2), bon comme mauvais mot
# de passe : pas d'oracle « nom de superutilisateur ».
out=$(psql_as regress_su "$GOOD" "SELECT current_user") || true
check_contains "fenêtre, worker présent : superutilisateur non exempté refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
client_out="$client_out$out"
out=$(psql_as regress_su "$BAD" "SELECT current_user") || true
check_contains "fenêtre, worker présent : superutilisateur, mauvais mot de passe : même réponse" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
client_out="$client_out$out"
check_not_contains "fenêtre : pas de HINT non plus pour un superutilisateur" "HINT" "$out"
# (vérification 7, 8) voie locale de secours (voir plus haut)
out=$(psql_local regress_su_peer) || true
check_contains "fenêtre, rescue_roles vide : superutilisateur en peer refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
psql_admin "ALTER SYSTEM SET pg_pass_policy.rescue_roles = 'regress_su_peer, regress_su_peer2, regress_su_nopeer, regress_su, regress_peer_plain'" >/dev/null
psql_admin "SELECT pg_reload_conf()" >/dev/null
sleep 1
out=$(psql_local regress_su) || true
check_contains "fenêtre : superutilisateur listé en trust sur socket Unix refusé (57P03, peer seulement)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
out=$(psql_local regress_su_peer) || true
rescue_t0=$SECONDS
check_eq "fenêtre : superutilisateur listé dans rescue_roles en peer accepté" "regress_su_peer" "$out"
out=$(psql_local regress_su_unlisted) || true
check_contains "fenêtre : superutilisateur en peer non listé refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
out=$(psql_local regress_peer_plain) || true
check_contains "fenêtre : rôle ordinaire listé en peer refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
out=$(psql_local regress_su_nopeer) || true
check_contains "fenêtre : superutilisateur listé dont le contrôle peer échoue : 57P03 (pas d'oracle)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
out=$(psql_local regress_window) || true
check_contains "fenêtre : rôle ordinaire en trust sur socket Unix refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
out=$("$PPP_BINDIR/psql" -X -q -At -w -h 127.0.0.1 -p "$PPP_PORT" -U regress_su_tcp -d "$PPP_DB" -c "SELECT current_user" 2>&1) || true
check_contains "fenêtre : superutilisateur en trust TCP refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
psql_admin "SELECT pass_policy.shmem_lock_role('regress_su_peer', NULL)" >/dev/null
out=$(psql_local regress_su_peer) || true
check_contains "fenêtre : superutilisateur en peer verrouillé en shmem : refusé « locked »" "is locked by pg_pass_policy" "$out"
psql_admin "SELECT pass_policy.shmem_unlock_role('regress_su_peer')" >/dev/null
out=$(psql_local regress_su_peer) || true
check_eq "fenêtre : verrou shmem levé, superutilisateur en peer de nouveau accepté" "regress_su_peer" "$out"
out=$(psql_local regress_su_peer) || true
# (vérification 10, (4)) admissions de secours journalisées une fois par rôle
# et par minute : trois admissions de regress_su_peer, un seul LOG ; celle de
# regress_su_peer2 dans la même minute a le sien (limite par rôle, pas pour
# toute l'instance)
rescue_log='admitted by peer authentication before the lock state is loaded'
n_rescue() { tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -c "superuser \"$1\" $rescue_log" || true; }
check_eq "fenêtre : 3 admissions de secours du même rôle dans la minute, 1 LOG" "1" "$(n_rescue regress_su_peer)"
out=$(psql_local regress_su_peer2) || true
check_eq "fenêtre : second rôle de secours accepté" "regress_su_peer2" "$out"
check_eq "fenêtre : le second rôle a son propre LOG dans la même minute" "1" "$(n_rescue regress_su_peer2)"
# Rien sur l'état interne n'est envoyé au client non authentifié (constat 1)
check_not_contains "fenêtre : la sortie du client ne mentionne ni le worker, ni exempt_roles, ni rescue_roles, ni peer" "worker|exempt|rescue|peer" "$client_out"
# … l'information complète est dans le journal du serveur (HINT du LOG)
out=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -A2 'refusing connections until the background worker has loaded the lock state' | grep 'HINT:' | head -1)
check_contains "fenêtre : le LOG serveur cite exempt_roles, rescue_roles en peer et les superutilisateurs sans worker" \
	"exempt_roles can connect, superusers listed in pg_pass_policy.rescue_roles through peer authentication only, and any superuser once no worker has published its PID 10 seconds" "$out"
out=$(psql_admin "SELECT last_reload IS NULL FROM pass_policy.worker_status()")
check_eq "fenêtre : aucun rechargement réussi (role_state introuvable)" "t" "$out"
out=$(psql_admin "SELECT locks_loaded FROM pass_policy.worker_status()")
check_eq "fenêtre : worker_status().locks_loaded = false" "f" "$out"
# Pendant la fenêtre maintenue ouverte, les relances (5 s) ne refont que la
# synchronisation : pas de tour complet (last_run inchangé), et le LOG
# « persisted locks » ne concerne pas ce cas (revue finale 8, constat 5).
lr0=$(psql_admin "SELECT coalesce(last_run::text, 'null') FROM pass_policy.worker_status()")
sleep 11
n=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -c 'worker shared memory synchronisation failed' || true)
check_eq "fenêtre : la synchronisation est relancée sans attendre ($n échecs journalisés)" "1" "$( [ "$n" -ge 3 ] && echo 1 || echo 0)"
out=$(psql_admin "SELECT coalesce(last_run::text, 'null') FROM pass_policy.worker_status()")
check_eq "fenêtre : les relances ne refont pas le tour complet (last_run inchangé)" "$lr0" "$out"
n=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -c 'refusing connections until the background worker has loaded the lock state' || true)
if [ "$n" -ge 1 ] && [ "$n" -lt 9 ]; then
	ok "fenêtre : LOG limité ($n ligne(s) pour 9 refus)"
else
	fail "fenêtre : LOG attendu entre 1 et 8 fois, obtenu $n"
fi
# (vérification 10, (4) ; vérification 11, (4) et (9)) une minute après le
# premier LOG de regress_su_peer, le worker journalise lui-même les deux
# admissions non journalisées, sans attendre une admission suivante. Attente
# réelle de 61 s (pas de GUC de test, docs/TESTING.md) : la fenêtre doit rester
# ouverte (locks_loaded = false) tout du long, vérifié avant et après, pour
# qu'un échec soit explicite plutôt qu'intermittent.
check_eq "fenêtre : toujours ouverte avant l'attente d'une minute (locks_loaded = false)" "f" \
	"$(psql_admin "SELECT locks_loaded FROM pass_policy.worker_status()")"
while [ $((SECONDS - rescue_t0)) -le 61 ]; do sleep 1; done
check_eq "fenêtre : toujours ouverte après l'attente d'une minute (locks_loaded = false)" "f" \
	"$(psql_admin "SELECT locks_loaded FROM pass_policy.worker_status()")"
rescue_flush() { tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -c "$1 of superuser \"regress_su_peer\" by peer authentication before the lock state was loaded $2 not logged" || true; }
flush_seen() { [ "$(rescue_flush "$@")" = 1 ]; }
if wait_until 15 flush_seen "2 admissions" were; then
	ok "fenêtre : le worker journalise les 2 admissions non journalisées une fois la période écoulée"
else
	fail "fenêtre : pas de LOG du worker pour les 2 admissions non journalisées"
fi
out=$(psql_local regress_su_peer) || true
check_eq "fenêtre : admission de secours une minute plus tard" "regress_su_peer" "$out"
check_eq "fenêtre : nouveau LOG de secours après une minute" "2" "$(n_rescue regress_su_peer)"
out=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -A1 "superuser \"regress_su_peer\" $rescue_log" | tail -1)
check_not_contains "fenêtre : ce LOG ne recompte pas les admissions déjà journalisées par le worker" "earlier admission" "$out"
# une admission de plus dans la période : journalisée par le worker à la
# fermeture de la fenêtre (aucune admission ne reste non journalisée)
out=$(psql_local regress_su_peer) || true
check_eq "fenêtre : admission de secours dans la période, pas de nouveau LOG" "regress_su_peer|2" "$out|$(n_rescue regress_su_peer)"
psql_admin "ALTER TABLE pass_policy.role_state_hidden RENAME TO role_state" >/dev/null
if wait_for 30 "SELECT last_reload IS NOT NULL FROM pass_policy.worker_status()"; then
	ok "fenêtre, worker_interval = 0 : le rechargement est retenté sans SIGHUP"
else
	fail "fenêtre, worker_interval = 0 : pas de rechargement après le retour de role_state"
fi
if wait_until 15 flush_seen "1 admission" was; then
	ok "fenêtre fermée : le worker journalise l'admission restée non journalisée"
else
	fail "fenêtre fermée : admission de secours restée non journalisée"
fi
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_contains "fenêtre fermée : refus « locked »" "is locked by pg_pass_policy" "$out"
out=$(psql_as regress_window "$GOOD" "SELECT current_user") || true
check_eq "fenêtre fermée : rôle non verrouillé accepté (échecs de la fenêtre non comptés)" "regress_window" "$out"
out=$(psql_admin "SELECT locks_loaded FROM pass_policy.worker_status()")
check_eq "fenêtre fermée : worker_status().locks_loaded = true" "t" "$out"
out=$(psql_as regress_trust_locked "" "SELECT current_user") || true
check_contains "fenêtre fermée : rôle verrouillé par trust refusé (locked)" "is locked by pg_pass_policy" "$out"
cp "$PPP_TMP/pg_hba.conf.orig" "$PPP_TMP/data/pg_hba.conf"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.rescue_roles" >/dev/null
psql_admin "SELECT pg_reload_conf()" >/dev/null
psql_admin "SELECT pass_policy.unlock_role('regress_trust_locked')" >/dev/null
psql_admin "DROP ROLE regress_trust_locked" >/dev/null
psql_admin "DROP ROLE regress_su_peer; DROP ROLE regress_su_peer2; DROP ROLE regress_su_nopeer; DROP ROLE regress_su_tcp" >/dev/null
psql_admin "DROP ROLE regress_su_unlisted; DROP ROLE regress_peer_plain" >/dev/null
psql_admin "SELECT pass_policy.unlock_role('regress_lock')" >/dev/null
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "fenêtre fermée : unlock_role, connexion acceptée" "regress_lock" "$out"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.worker_interval" >/dev/null

# --- worker qui ne démarre jamais (revue finale 7, constat 7 ; revue finale 8)
# pg_pass_policy.database inexistante : le worker échoue à la connexion et ne
# publie jamais son PID. La fenêtre reste fermée pour les rôles ordinaires ;
# un superutilisateur non exempté est refusé comme eux pendant les
# PPP_WORKER_MISSING_GRACE_SECS (10 s) qui suivent le démarrage, puis se
# connecte (worker démontrablement absent), mais reste soumis à un verrou
# posé en shmem ; le hook l'écrit dans le log (LOG) au plus une fois par
# minute, sans rien en dire au client.
psql_admin "ALTER SYSTEM SET pg_pass_policy.database = 'ppp_no_such_db'" >/dev/null
log0=$(wc -l <"$PPP_TMP/server.log")
restart_server
out=$(psql_as regress_su "$GOOD" "SELECT current_user") || true
check_contains "worker absent depuis moins de 10 s : superutilisateur non exempté refusé (57P03)" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
out=$(psql_as regress_window "$GOOD" "SELECT current_user") || true
check_contains "worker absent : un rôle ordinaire reçoit 57P03" "FATAL: +pg_pass_policy: lock state not loaded yet, retry" "$out"
warn='pg_pass_policy: worker has not loaded the lock state yet \(worker_pid = 0\)'
client_out=""
deadline=$((SECONDS + 25))
while [ "$SECONDS" -lt "$deadline" ]; do
	client_out="$client_out$(psql_as regress_window "$GOOD" || true)"
	tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -qE "$warn" && break
	sleep 1
done
for i in 1 2 3; do client_out="$client_out$(psql_as regress_window "$GOOD" || true)"; done
check_not_contains "worker absent : la sortie du client ne mentionne ni le worker ni exempt_roles (constat 1)" "worker|exempt" "$client_out"
n=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -cE "LOG: +$warn" || true)
check_eq "worker absent : LOG worker_pid = 0 émis une fois (limité à 1 par minute)" "1" "$n"
n=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -cE "WARNING: +$warn" || true)
check_eq "worker absent : plus de WARNING (LOG seulement)" "0" "$n"
out=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -A2 -E "$warn" | head -3)
check_contains "worker absent : le LOG cite max_worker_processes et pg_pass_policy.database" "max_worker_processes and pg_pass_policy.database" "$out"
out=$(psql_as regress_su "$GOOD" "SELECT current_user") || true
check_eq "worker absent depuis plus de 10 s : un superutilisateur non exempté se connecte" "regress_su" "$out"
out=$(psql_as regress_su "$BAD" "SELECT current_user") || true
check_contains "worker absent : superutilisateur, mauvais mot de passe : refus normal" "password authentication failed" "$out"
for i in 1 2 3 4; do psql_as regress_su "$BAD" >/dev/null || true; done
out=$(psql_as regress_su "$GOOD" "SELECT current_user") || true
check_contains "worker absent : superutilisateur verrouillé en shmem après 5 échecs, refusé" "is locked by pg_pass_policy" "$out"
psql_admin "ALTER SYSTEM RESET pg_pass_policy.database" >/dev/null

# --- extension non fiable au démarrage (revue finale 8, constat 4) -----------
# Schéma pass_policy cédé à un rôle non superutilisateur : le worker ne fait
# rien et la fenêtre de démarrage reste fermée. Ce n'est plus silencieux :
# un WARNING (propriétaire du schéma en DETAIL), au plus une fois par minute.
nsp_owner=$(psql_admin "SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'pass_policy'")
psql_admin "ALTER SCHEMA pass_policy OWNER TO regress_window" >/dev/null
log0=$(wc -l <"$PPP_TMP/server.log")
restart_server
sleep 8
n=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -c 'WARNING: .*extension in database .* is not trusted, the worker does nothing' || true)
check_eq "extension non fiable : WARNING du worker émis une fois (limité à 1 par minute)" "1" "$n"
out=$(tail -n "+$((log0 + 1))" "$PPP_TMP/server.log" | grep -A1 'is not trusted, the worker does nothing' | head -2)
check_contains "extension non fiable : le DETAIL nomme le propriétaire du schéma" 'owned by role "regress_window"' "$out"
out=$(psql_admin "SELECT locks_loaded FROM pass_policy.worker_status()")
check_eq "extension non fiable : locks_loaded = false" "f" "$out"
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_contains "extension non fiable : fenêtre fermée (57P03)" "lock state not loaded yet" "$out"
psql_admin "ALTER SCHEMA pass_policy OWNER TO $nsp_owner" >/dev/null
if wait_for 30 "SELECT locks_loaded FROM pass_policy.worker_status()"; then
	ok "extension de nouveau fiable : fenêtre fermée par le worker"
else
	fail "extension de nouveau fiable : locks_loaded reste faux"
fi
out=$(psql_as regress_lock "$GOOD" "SELECT current_user") || true
check_eq "extension de nouveau fiable : connexion acceptée" "regress_lock" "$out"

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

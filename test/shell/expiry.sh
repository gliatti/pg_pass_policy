#!/usr/bin/env bash
# expiry.sh — expiration par le worker et refus de connexion (SPEC §3.3, §6.4, §7)
#
# PostgreSQL ne dit pas au client que le mot de passe a expiré : le client reçoit
# « password authentication failed », la raison (« User "x" has an expired
# password ») n'est écrite que dans le log serveur. On vérifie les deux.
set -euo pipefail
. "$(dirname "$0")/common.sh"

PWD1='Expiry-First#2024'

# shellcheck disable=SC2119 # pas de surcharge de configuration
ppp_start

psql_admin "SELECT pass_policy.create_profile('p_exp',
  '{\"max_age\": \"1 second\", \"grace_period\": \"1 second\", \"warn_before\": \"1 second\", \"min_age\": \"0\", \"max_failures\": 0}')" >/dev/null
psql_admin "CREATE ROLE regress_exp LOGIN"
psql_admin "SELECT pass_policy.assign_profile('regress_exp', 'p_exp')" >/dev/null
psql_admin "ALTER ROLE regress_exp PASSWORD '$PWD1'"

out=$(psql_admin "SELECT password_changed_at IS NOT NULL, expires_at IS NOT NULL FROM pass_policy.role_state WHERE role_name = 'regress_exp'")
check_eq "role_state renseigné par le hook" "t|t" "$out"

# Le worker (worker_interval = 2) doit poser VALID UNTIL = grace_until, déjà passé
if wait_for 30 "SELECT rolvaliduntil IS NOT NULL AND rolvaliduntil < now() FROM pg_roles WHERE rolname = 'regress_exp'"; then
	ok "le worker a posé rolvaliduntil (passé)"
else
	fail "rolvaliduntil non posé par le worker" "$(psql_admin "SELECT rolvaliduntil FROM pg_roles WHERE rolname = 'regress_exp'")"
fi
out=$(psql_admin "SELECT abs(extract(epoch FROM r.rolvaliduntil - s.grace_until)) < 2 FROM pg_roles r JOIN pass_policy.role_state s ON s.role_name = r.rolname WHERE r.rolname = 'regress_exp'")
check_eq "rolvaliduntil = grace_until" "t" "$out"

out=$(psql_as regress_exp "$PWD1") && rc=0 || rc=$?
check_eq "connexion refusée après expiration" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "message client" "password authentication failed" "$out"
sleep 0.5
if grep -q 'regress_exp" has an expired password' "$PPP_TMP/server.log"; then
	ok "log serveur : expired password"
else
	fail "log serveur sans « has an expired password »"
fi

if wait_for 30 "SELECT count(*) > 0 FROM pass_policy.audit_log WHERE event_type = 'password_expired' AND role_name = 'regress_exp'"; then
	ok "audit password_expired"
else
	fail "pas d'audit password_expired"
fi
# expiry_warning n'est pas exigé ici : la fenêtre d'alerte (1 s) peut tomber
# entre deux tours du worker. L'alerte est testée de façon déterministe dans
# test/sql/70_maintenance.sql.
out=$(psql_admin "SELECT count(*) FROM pass_policy.audit_log WHERE event_type = 'expiry_warning' AND role_name = 'regress_exp'")
log "info : $out alerte(s) expiry_warning"
out=$(psql_admin "SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_exp'")
check_eq "v_role_status = expired" "expired" "$out"
out=$(psql_admin "SELECT role_name FROM pass_policy.v_expiring WHERE role_name = 'regress_exp'")
check_eq "présent dans v_expiring" "regress_exp" "$out"

# Rotation : le mot de passe renvoyé permet de se connecter
psql_admin "SELECT pass_policy.alter_profile('p_exp', '{\"max_age\": \"1 hour\", \"grace_period\": \"1 hour\", \"warn_before\": \"1 minute\"}')" >/dev/null
newpwd=$(psql_admin "SELECT pass_policy.rotate_password('regress_exp')")
out=$(psql_as regress_exp "$newpwd" "SELECT current_user") || true
check_eq "connexion avec le mot de passe renvoyé par rotate_password" "regress_exp" "$out"
# SPEC §8.1 : y compris dans les lignes CONTEXT des messages LOG émis pendant
# l'ALTER ROLE dynamique de rotate_password
if grep -qF -- "$newpwd" "$PPP_TMP/server.log"; then
	fail "le mot de passe généré apparaît dans le log serveur" "$(grep -nF -- "$newpwd" "$PPP_TMP/server.log" | sed "s/$(printf '%s' "$newpwd" | sed 's/[]\/$*.^[]/\\&/g')/<MOT DE PASSE>/g" | head -n 5)"
else
	ok "le mot de passe généré n'est pas dans le log serveur"
fi
out=$(psql_admin "SELECT rolvaliduntil > now() + interval '1 hour' FROM pg_roles WHERE rolname = 'regress_exp'")
check_eq "rolvaliduntil repoussé après rotation" "t" "$out"
out=$(psql_admin "SELECT status FROM pass_policy.v_role_status WHERE role_name = 'regress_exp'")
check_eq "v_role_status = ok après rotation" "ok" "$out"

# expire_password : connexion refusée immédiatement
psql_admin "SELECT pass_policy.expire_password('regress_exp')" >/dev/null
out=$(psql_as regress_exp "$newpwd") && rc=0 || rc=$?
check_eq "expire_password : connexion refusée" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
# … et le worker ne repousse pas VALID UNTIL tant que must_change est vrai
wait_worker_run 30 || true
out=$(psql_as regress_exp "$newpwd") && rc=0 || rc=$?
check_eq "expire_password : toujours refusé après un tour du worker" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"

ppp_finish

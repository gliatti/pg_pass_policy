#!/usr/bin/env bash
# auto_explain.sh — aucun mot de passe ni vérificateur SCRAM dans le log serveur
# quand auto_explain journalise les requêtes imbriquées (SPEC §8.1, §11).
#
# auto_explain.log_nested_statements = on + log_verbose = on écrivent le texte
# et les paramètres ($1 = …) des requêtes exécutées par SPI : l'extension
# désactive auto_explain le temps de ses propres requêtes (hook C,
# _set_password, run_maintenance).
set -euo pipefail
. "$(dirname "$0")/common.sh"

PLAIN='Explain-Plain#2024'

ppp_start "shared_preload_libraries = 'pg_pass_policy,auto_explain'" \
	"auto_explain.log_min_duration = 0" \
	"auto_explain.log_nested_statements = on" \
	"auto_explain.log_verbose = on"

psql_admin "SELECT pass_policy.create_profile('p_ae', '{\"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE regress_ae LOGIN"
psql_admin "SELECT pass_policy.assign_profile('regress_ae', 'p_ae')" >/dev/null
psql_admin "CREATE ROLE regress_ae_grp NOLOGIN"

pwd1=$(psql_admin "SELECT pass_policy.rotate_password('regress_ae')")
check_eq "rotate_password renvoie un mot de passe" "24" "${#pwd1}"
out=$(psql_as regress_ae "$pwd1" "SELECT current_user") || true
check_eq "connexion avec le mot de passe de rotate_password" "regress_ae" "$out"

psql_admin "SELECT pass_policy.create_rotation_pair('ae_pair', 'regress_ae_a', 'regress_ae_b', 'regress_ae_grp')" >/dev/null
pwd2=$(psql_admin "SELECT password FROM pass_policy.switch_rotation_pair('ae_pair')")
pwd3=$(psql_admin "SELECT password FROM pass_policy.switch_rotation_pair('ae_pair')")
check_eq "switch_rotation_pair renvoie un mot de passe" "24" "${#pwd3}"

psql_admin "ALTER ROLE regress_ae PASSWORD '$PLAIN'"
out=$(psql_as regress_ae "$PLAIN" "SELECT current_user") || true
check_eq "connexion après ALTER ROLE … PASSWORD" "regress_ae" "$out"

psql_admin "SELECT count(*) FROM pass_policy.run_maintenance()" >/dev/null
wait_worker_run 30 || true
sleep 1

# auto_explain est bien actif (sinon le test ne prouverait rien)
n=$(grep -c 'Query Text:' "$PPP_TMP/server.log" || true)
check_eq "auto_explain journalise des requêtes (> 0)" "1" "$( [ "$n" -gt 0 ] && echo 1 || echo 0)"

for label in pwd1 pwd2 pwd3 PLAIN; do
	v=${!label}
	n=$(grep -cF -- "$v" "$PPP_TMP/server.log" || true)
	check_eq "mot de passe $label absent du log serveur" "0" "$n"
done
n=$(grep -c 'SCRAM-SHA-256\$' "$PPP_TMP/server.log" || true)
check_eq "aucun vérificateur SCRAM dans le log serveur" "0" "$n"
n=$(grep -c 'Query Parameters:.*SCRAM' "$PPP_TMP/server.log" || true)
check_eq "aucun paramètre SCRAM journalisé par auto_explain" "0" "$n"

# Les mots de passe restent fonctionnels (la garde ne casse rien)
active=$(psql_admin "SELECT active_role FROM pass_policy.rotation_pair WHERE pair_name = 'ae_pair'")
out=$(psql_as "$active" "$pwd3" "SELECT current_user") || true
check_eq "connexion du rôle actif de la paire" "$active" "$out"

ppp_finish

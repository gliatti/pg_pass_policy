#!/usr/bin/env bash
# scs_off.sh — CREATE EXTENSION et dictionnaire avec
# standard_conforming_strings = off (SPEC §3.5, §11).
#
# Le script d'extension s'exécute avec la valeur du serveur : un littéral
# '\' y aurait un autre sens (et CREATE EXTENSION échouait). La colonne
# générée word_sha256 écrit l'antislash chr(92) ; le condensat d'un mot qui
# en contient doit être celui de ses octets bruts, comme le calcule le hook.
set -euo pipefail
. "$(dirname "$0")/common.sh"

# ppp_start fait CREATE EXTENSION : il échoue si le script ne passe pas
ppp_start "standard_conforming_strings = off" "escape_string_warning = off"

out=$(psql_admin "SHOW standard_conforming_strings")
check_eq "standard_conforming_strings = off" "off" "$out"
out=$(psql_admin "SELECT extversion FROM pg_extension WHERE extname = 'pg_pass_policy'")
check_eq "CREATE EXTENSION réussi" "1.0" "$out"

# E'' : même sens quelle que soit la valeur du paramètre
psql_admin "SELECT pass_policy.load_dictionary(ARRAY[E'anti\\\\slash2024!', E'double\\\\\\\\bs2024!'])" >/dev/null
out=$(psql_admin "SELECT count(*) FROM pass_policy.dictionary WHERE word IN (E'anti\\\\slash2024!', E'double\\\\\\\\bs2024!') AND word_sha256 = sha256(convert_to(word, 'UTF8'))")
check_eq "word_sha256 = SHA-256 des octets bruts (mots avec antislash)" "2" "$out"
out=$(psql_admin "SELECT length(word) FROM pass_policy.dictionary WHERE word = E'anti\\\\slash2024!'")
check_eq "un seul antislash stocké" "15" "$out"

out=$(psql_admin "SELECT pass_policy.check_password('regress_other', E'Anti\\\\Slash2024!')")
check_contains "PPP-018 : mot du dictionnaire avec antislash (casse différente)" "PPP-018" "$out"
out=$(psql_admin "SELECT pass_policy.check_password('regress_other', E'Double\\\\\\\\BS2024!')")
check_contains "PPP-018 : mot avec deux antislashs consécutifs" "PPP-018" "$out"
out=$(psql_admin "SELECT coalesce(pass_policy.check_password('regress_other', E'Anti\\\\Slash2025!'), 'NULL')")
check_eq "mot voisin accepté" "NULL" "$out"

# Et par un vrai ALTER ROLE (hook)
psql_admin "CREATE ROLE regress_scs LOGIN"
out=$(psql_admin "ALTER ROLE regress_scs PASSWORD E'ANTI\\\\slash2024!'" 2>&1) && rc=0 || rc=$?
check_eq "ALTER ROLE refusé par le dictionnaire" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "code PPP-018" "PPP-018" "$out"

ppp_finish

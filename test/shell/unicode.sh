#!/usr/bin/env bash
# unicode.sh — PPP-017 / PPP-018 insensibles à la casse sur des lettres non
# ASCII avec une locale non C (SPEC §6.2, §8.5).
#
# Les autres scripts tournent en --locale=C (chemin ASCII) ; ici l'instance est
# créée en C.UTF-8 pour emprunter le chemin multi-octets de ppp_lower(), celui
# qui convertit par points de code (towlower) dans un tampon effacé.
set -euo pipefail
. "$(dirname "$0")/common.sh"

if ! locale -a 2>/dev/null | grep -qiE '^C\.(UTF-8|utf8)$'; then
	log "locale C.UTF-8 absente : test ignoré"
	ok "ignoré (pas de locale C.UTF-8)"
	ppp_finish
	exit 0
fi
export PPP_LOCALE=C.UTF-8
export PGCLIENTENCODING=UTF8

ppp_start

out=$(psql_admin "SELECT lower('ÉTÉ') = 'été'")
check_eq "lower() SQL convertit les lettres non ASCII (locale non C)" "t" "$out"

psql_admin "SELECT pass_policy.create_profile('p_uni', '{\"min_age\": \"0\"}')" >/dev/null
psql_admin "CREATE ROLE \"regress_été\" LOGIN"
psql_admin "SELECT pass_policy.assign_profile('regress_été', 'p_uni')" >/dev/null
psql_admin "SELECT pass_policy.load_dictionary(ARRAY['étésoleil2024!'])" >/dev/null
out=$(psql_admin "SELECT word FROM pass_policy.dictionary WHERE word = 'étésoleil2024!'")
check_eq "mot chargé en minuscules" "étésoleil2024!" "$out"

# Dictionnaire : même mot avec des majuscules non ASCII
out=$(psql_admin "SELECT pass_policy.check_password('regress_other', 'ÉtéSoleil2024!')")
check_contains "PPP-018 : « ÉtéSoleil2024! » = « étésoleil2024! »" "PPP-018" "$out"
out=$(psql_admin "SELECT pass_policy.check_password('regress_other', 'ÉTÉsoleil2024!')")
check_contains "PPP-018 : majuscules non ASCII en tête" "PPP-018" "$out"
out=$(psql_admin "SELECT coalesce(pass_policy.check_password('regress_other', 'ÉtéSoleil2025!'), 'NULL')")
check_eq "mot voisin accepté" "NULL" "$out"

# Nom de rôle : contenu en majuscules et inversé
out=$(psql_admin "SELECT pass_policy.check_password('regress_été', 'Xx-REGRESS_ÉTÉ-2024#')")
check_contains "PPP-017 : nom de rôle en majuscules non ASCII" "PPP-017" "$out"
out=$(psql_admin "SELECT pass_policy.check_password('regress_été', 'Xx-ÉTÉ_SSERGER-2024#')")
check_contains "PPP-017 : nom de rôle inversé" "PPP-017" "$out"

# (clôture) PPP-020 : caractères Unicode de contrôle, de format ou d'espace
# invisible refusés (base UTF8) ; une lettre accentuée reste acceptée
for cp in 200B 0085 00A0 2028 FEFF 3000; do
	ch=$(printf "\\u$cp")
	out=$(psql_admin "SELECT pass_policy.check_password('regress_été', 'Xx-Pass${ch}word-2024#')")
	check_contains "PPP-020 : U+$cp refusé" "PPP-020" "$out"
done
out=$(psql_admin "SELECT coalesce(pass_policy.check_password('regress_été', 'Xx-Pässwörd-2024#'), 'NULL')")
check_eq "lettres accentuées acceptées" "NULL" "$out"
out=$(psql_admin "ALTER ROLE \"regress_été\" PASSWORD 'Xx-Pass$(printf '​')word-2024#'" 2>&1) || true
check_contains "ALTER ROLE avec U+200B refusé (hook)" "PPP-020" "$out"

# Et par un vrai ALTER ROLE (hook)
out=$(psql_admin "ALTER ROLE \"regress_été\" PASSWORD 'ÉtéSoleil2024!'" 2>&1) && rc=0 || rc=$?
check_eq "ALTER ROLE refusé par le dictionnaire" "1" "$( [ "$rc" -ne 0 ] && echo 1 || echo 0)"
check_contains "code PPP-018" "PPP-018" "$out"
check_not_contains "le mot de passe n'est pas dans le message" "ÉtéSoleil2024" "$out"
psql_admin "ALTER ROLE \"regress_été\" PASSWORD 'Ünïcôdé-Accepté#2024'"
out=$(psql_as "regress_été" 'Ünïcôdé-Accepté#2024' "SELECT current_user") || true
check_eq "connexion avec un mot de passe non ASCII accepté" "regress_été" "$out"
n=$(grep -cF -- 'Ünïcôdé-Accepté#2024' "$PPP_TMP/server.log" || true)
check_eq "mot de passe absent du log serveur" "0" "$n"

ppp_finish

#!/usr/bin/env bash
# test-instance.sh — temporary PostgreSQL instance for the web back-office tests.
#
#   test-instance.sh start DIR PORT   initdb + start, CREATE EXTENSION pg_pass_policy,
#                                     create the role pgpp_web (member of
#                                     pass_policy_admin, CREATEROLE for the tests)
#   test-instance.sh stop DIR         stop and remove DIR
#
# DIR is removed (rm -rf) only when it carries the marker file written by
# "start" (DIR/.pgpp-web-test-instance): a mistyped DIR (".", "$HOME", an
# existing data directory...) is refused, never erased.  "start" accepts a
# DIR that does not exist, an empty one, or one created by a previous start.
#
# Passwords never appear on a command line, in SQL text, in a URL or in the
# shell history: the superuser password is generated into a 0600 file handed
# to initdb --pwfile, the pgpp_web password is generated server side by
# pass_policy.rotate_password() and both are written to DIR/pgpass (0600),
# to be used through PGPASSFILE.
#
# "start" prints the environment to export for pytest:
#   PGPASSFILE, PGPP_TEST_URL (role pgpp_web), PGPP_TEST_SUPER_URL (superuser).
#
# The extension must be installed in the PostgreSQL pointed to by pg_config
# (make install) and loaded via shared_preload_libraries: the socket directory
# is not used (the path may exceed the Unix socket length limit), everything
# goes through TCP on 127.0.0.1 with scram-sha-256.
set -euo pipefail

cmd=${1:-}
dir=${2:-}
port=${3:-54332}
if [ -z "$cmd" ] || [ -z "$dir" ]; then
	echo "usage: $0 start DIR [PORT] | stop DIR" >&2
	exit 2
fi
bindir=$(pg_config --bindir)
superuser=pgpp_super
db=postgres

unset PGSERVICE PGSERVICEFILE PGPASSFILE PGOPTIONS PGSSLMODE PGDATABASE PGUSER PGHOST PGPORT PGPASSWORD || true
export PGCONNECT_TIMEOUT=10

# pgpass format: backslash and colon inside a field must be escaped
pgpass_escape() {
	sed -e 's/\\/\\\\/g' -e 's/:/\\:/g'
}

marker=.pgpp-web-test-instance

# refuse to erase a directory this script did not create
check_owned() {
	if [ -e "$dir" ] && [ ! -f "$dir/$marker" ]; then
		if [ -d "$dir" ] && [ -z "$(ls -A "$dir")" ]; then
			return 0
		fi
		echo "refusing to remove $dir: not a test instance created by $0 (no $marker)" >&2
		exit 1
	fi
}

psql_super() {
	PGPASSFILE="$dir/pgpass" "$bindir/psql" -X -q -At -v ON_ERROR_STOP=1 \
		-h 127.0.0.1 -p "$port" -U "$superuser" -d "$db" "$@"
}

case "$cmd" in
start)
	if [ -e "$dir/data/postmaster.pid" ]; then
		echo "instance already running in $dir" >&2
		exit 1
	fi
	check_owned
	rm -rf "$dir"
	mkdir -p "$dir"
	chmod 700 "$dir"
	umask 077
	: >"$dir/$marker"
	# superuser password: generated, written to a file for initdb --pwfile
	python3 -c 'import secrets; print(secrets.token_urlsafe(24))' >"$dir/super.pw"
	"$bindir/initdb" -D "$dir/data" -U "$superuser" -A scram-sha-256 --pwfile="$dir/super.pw" \
		--no-sync -E UTF8 --locale=C >"$dir/initdb.log" 2>&1 || {
		cat "$dir/initdb.log"
		exit 1
	}
	printf '127.0.0.1:%s:*:%s:%s\n' "$port" "$superuser" "$(pgpass_escape <"$dir/super.pw")" >"$dir/pgpass"
	rm -f "$dir/super.pw"
	cat >>"$dir/data/postgresql.conf" <<CONF

# --- pg_pass_policy web tests ---
shared_preload_libraries = 'pg_pass_policy'
pg_pass_policy.database = '$db'
pg_pass_policy.worker_interval = 2
password_encryption = 'scram-sha-256'
listen_addresses = '127.0.0.1'
port = $port
unix_socket_directories = ''
log_connections = on
log_min_messages = warning
CONF
	cat >"$dir/data/pg_hba.conf" <<HBA
local   all   all                 trust
host    all   all   127.0.0.1/32  scram-sha-256
host    all   all   ::1/128       scram-sha-256
HBA
	"$bindir/pg_ctl" -D "$dir/data" -l "$dir/server.log" -w start >/dev/null
	# CREATE EXTENSION may fail transiently while the extension is being rebuilt
	for attempt in 1 2 3 4 5 6; do
		if psql_super -c "CREATE EXTENSION IF NOT EXISTS pg_pass_policy" >/dev/null 2>"$dir/ext.err"; then
			break
		fi
		if [ "$attempt" = 6 ]; then
			cat "$dir/ext.err" >&2
			"$bindir/pg_ctl" -D "$dir/data" -m immediate stop >/dev/null 2>&1 || true
			exit 1
		fi
		sleep 5
	done
	psql_super -c "CREATE ROLE pgpp_web LOGIN CREATEROLE IN ROLE pass_policy_admin" >/dev/null
	# the password is generated server side and returned once: it goes to the
	# pgpass file only (never on a command line, never in the SQL text)
	psql_super -c "SELECT pass_policy.rotate_password('pgpp_web')" | pgpass_escape |
		sed "s/^/127.0.0.1:$port:*:pgpp_web:/" >>"$dir/pgpass"
	chmod 600 "$dir/pgpass"
	echo "export PGPASSFILE=$dir/pgpass"
	echo "export PGPP_TEST_URL=postgresql://pgpp_web@127.0.0.1:$port/$db"
	echo "export PGPP_TEST_SUPER_URL=postgresql://$superuser@127.0.0.1:$port/$db"
	;;
stop)
	[ -e "$dir" ] || exit 0
	check_owned
	if [ -d "$dir/data" ]; then
		"$bindir/pg_ctl" -D "$dir/data" -m fast -w stop >/dev/null 2>&1 || true
	fi
	rm -rf "$dir"
	;;
*)
	echo "unknown command: $cmd" >&2
	exit 2
	;;
esac

"""`pgpp-web-hash USER`: print a USER:bcrypt-hash entry for PGPP_WEB_BASIC_USERS.

The password is read from the terminal without echo (or from stdin when it
is not a terminal); it is never taken from the command line.
"""

from __future__ import annotations

import getpass
import sys

import bcrypt

# bcrypt only uses the first 72 bytes (bcrypt >= 5 raises beyond): a longer
# password is refused, here and by auth.verify_basic(), rather than truncated
BCRYPT_MAX_BYTES = 72


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] in ("-h", "--help"):
        print(
            "usage: pgpp-web-hash USER   (the password is read from the terminal)", file=sys.stderr
        )
        return 2
    user = args[0]
    if ":" in user or "," in user:
        print("the user name must not contain ':' or ','", file=sys.stderr)
        return 2
    if sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Password (again): "):
            print("passwords do not match", file=sys.stderr)
            return 1
    else:
        password = sys.stdin.readline().rstrip("\r\n")
    if len(password) < 12:
        print("the password must be at least 12 characters long", file=sys.stderr)
        return 1
    encoded = password.encode("utf-8")
    if len(encoded) > BCRYPT_MAX_BYTES:
        # bcrypt ignores (bcrypt >= 5: rejects) what lies beyond 72 bytes
        print(
            f"the password must not exceed {BCRYPT_MAX_BYTES} bytes in UTF-8"
            f" ({len(encoded)} given)",
            file=sys.stderr,
        )
        return 1
    digest = bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=12)).decode("ascii")
    print(f"{user}:{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

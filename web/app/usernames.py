"""The user name rule, shared by the authentication (proxy header, log
lines) and by the settings (PGPP_WEB_BASIC_USERS, checked at startup).

No import from the rest of the application: config.py and auth.py both
import it."""

from __future__ import annotations

import unicodedata

# longest accepted user name, in characters
USER_MAX_LENGTH = 128

# Unicode general categories refused anywhere in a user name.  A log viewer
# or a terminal renders them as a line break, as nothing or as a plain
# space, so that two distinct names would look alike:
#   Cc  control characters (C0, DEL, C1, NEL U+0085 included)
#   Cf  format characters (bidirectional overrides, zero-width joiners,
#       soft hyphen...)
#   Cs  surrogates (a lone surrogate is not a character)
#   Co  private use characters (no agreed glyph)
#   Cn  unassigned code points, in the Unicode version of the running
#       Python (unicodedata.unidata_version): a code point assigned by a
#       later version is refused until Python knows it
#   Zl  line separator U+2028
#   Zp  paragraph separator U+2029
#   Zs  space separators (no-break space U+00A0, ideographic space U+3000,
#       en / em spaces...), except the ASCII space U+0020, accepted inside
#       a name (never at either end)
# The list is explicit, not str.isprintable(), so that the rule is stated
# here rather than inherited.
REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"})


def user_name_problem(name: str) -> str | None:
    """Why `name` is not a valid user name, None if it is.

    A user name: 1 to USER_MAX_LENGTH characters, in NFC form, not starting
    with a combining mark, no character of REFUSED_CATEGORIES but the ASCII
    space, which is refused at either end.  Letters, marks and symbols of
    any script are accepted ("Émilie", "日本").

    NFC: "É" can be written U+00C9 or "E" followed by the combining acute
    accent U+0301; both render alike.  Only the precomposed (NFC) form is
    accepted, the other one is refused, never normalised: normalising would
    map two distinct byte sequences to a single name.  A leading combining
    mark would combine with whatever precedes the name in a log line."""
    if not name:
        return "empty"
    if len(name) > USER_MAX_LENGTH:
        return f"longer than {USER_MAX_LENGTH} characters"
    if name.strip(" ") != name:
        return "leading or trailing space"
    for char in name:
        if char != " " and unicodedata.category(char) in REFUSED_CATEGORIES:
            return (
                f"character U+{ord(char):04X} not allowed (category {unicodedata.category(char)})"
            )
    if unicodedata.category(name[0]).startswith("M"):
        return f"starts with a combining mark U+{ord(name[0]):04X}"
    if not unicodedata.is_normalized("NFC", name):
        return "not in Unicode NFC form (decomposed accents)"
    return None


def valid_user_name(name: str) -> bool:
    return user_name_problem(name) is None

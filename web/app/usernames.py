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

# Invisible characters outside REFUSED_CATEGORIES (marks, letters, a
# symbol), refused one by one.  Reference: the Unicode property
# Default_Ignorable_Code_Point (DerivedCoreProperties.txt), code points
# that a renderer shows as nothing, plus fillers and blanks drawn as an
# empty cell; a name holding one looks like the name without it:
#   U+034F           combining grapheme joiner (Mn)
#   U+115F, U+1160   Hangul choseong / jungseong fillers (Lo)
#   U+17B4, U+17B5   Khmer inherent vowels AQ / AA (Mn)
#   U+180B-U+180F    Mongolian free variation selectors (Mn; U+180E, the
#                    vowel separator, is Cf and listed for completeness)
#   U+2800           Braille pattern blank (So, not Default_Ignorable but
#                    drawn as a space)
#   U+FE00-U+FE0F    variation selectors 1-16 (Mn)
#   U+E0100-U+E01EF  variation selectors 17-256 (Mn)
# Not listed: the Hangul filler U+3164 and the halfwidth Hangul filler
# U+FFA0, not in NFKC form (both map to U+1160), refused by the NFKC check
# of user_name_problem().  Each code point above was checked one by one
# to be in NFKC form (unicodedata.is_normalized("NFKC", c)): the NFKC
# check would not refuse it.
INVISIBLE_CODE_POINTS = frozenset(
    {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800}
    | set(range(0x180B, 0x1810))
    | set(range(0xFE00, 0xFE10))
    | set(range(0xE0100, 0xE01F0))
)

# the rule in one line, quoted by the startup error on PGPP_WEB_BASIC_USERS
# (the length from USER_MAX_LENGTH, the rest in words)
USER_NAME_RULE = (
    f"1 to {USER_MAX_LENGTH} characters, in Unicode NFC and NFKC forms (no"
    " decomposed accent, no compatibility form), no leading combining mark,"
    " no control, format, surrogate, private use or unassigned character, no"
    " Unicode line, paragraph or space separator but the ASCII space inside the"
    " name, no invisible character (variation selectors, fillers...)"
)


def user_name_problem(name: str) -> str | None:
    """Why `name` is not a valid user name, None if it is.

    A user name: 1 to USER_MAX_LENGTH characters, in NFC and NFKC forms,
    not starting with a combining mark, no character of REFUSED_CATEGORIES
    but the ASCII space, which is refused at either end, and none of
    INVISIBLE_CODE_POINTS.  Letters, marks and symbols of
    any script are accepted ("Émilie", "日本").

    NFC: "É" can be written U+00C9 or "E" followed by the combining acute
    accent U+0301; both render alike.  Only the precomposed (NFC) form is
    accepted, the other one is refused, never normalised: normalising would
    map two distinct byte sequences to a single name.  A leading combining
    mark would combine with whatever precedes the name in a log line.

    NFKC: compatibility forms (fullwidth "ａｌｉｃｅ", ligature "ﬁ",
    mathematical alphanumerics "𝐚𝐥𝐢𝐜𝐞", superscripts...) look like, or are
    read as, their plain counterpart: refused as well, never mapped to it."""
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
        if ord(char) in INVISIBLE_CODE_POINTS:
            return f"character U+{ord(char):04X} not allowed (invisible)"
    if unicodedata.category(name[0]).startswith("M"):
        return f"starts with a combining mark U+{ord(name[0]):04X}"
    # NFKC implies NFC: the NFC check refuses nothing more, it is kept for
    # its more precise message (decomposed accents, not a compatibility form)
    if not unicodedata.is_normalized("NFC", name):
        return "not in Unicode NFC form (decomposed accents)"
    if not unicodedata.is_normalized("NFKC", name):
        return "not in Unicode NFKC form (compatibility character: fullwidth, ligature...)"
    return None


def valid_user_name(name: str) -> bool:
    return user_name_problem(name) is None

"""Conservative version comparison.

``compare`` returns -1/0/1, or ``None`` when the two strings cannot be compared
with confidence. Callers must treat ``None`` as "needs review", never as a match
or a non-match.

Supported: PEP 440 / semver-like dotted versions, and simple upstream versions
with an alphabetic suffix (``9.6p1``, ``2.0-beta9``, ``1.1.1w``). Not supported
on purpose: distro package versions (``1:9.6p1-3ubuntu13.4``, ``0:8.7p1-38.el9``),
because vendors backport fixes without changing the upstream version, and
comparing them as upstream versions would produce confident wrong answers.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_SIMPLE = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-._]?([a-z]+)\.?(\d*))?$", re.IGNORECASE)
_DISTRO_HINT = re.compile(r"(^\d+:)|ubuntu|deb\d|\.el\d|el\d_|\+dfsg|~|\.fc\d|-\d+\.\w+$", re.IGNORECASE)
_PRE = {"dev": -4, "a": -3, "alpha": -3, "b": -2, "beta": -2, "pre": -1, "rc": -1, "c": -1}

UNSUPPORTED_SCHEMES = {"rpm", "deb", "git", "dpkg"}


def looks_like_distro_version(v: str) -> bool:
    return bool(_DISTRO_HINT.search(v))


def _key(v: str) -> tuple[tuple[int, ...], int, int] | None:
    m = _SIMPLE.match(v.strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    word, num = (m.group(2) or "").lower(), int(m.group(3) or 0)
    if not word:
        rank = 0
    elif word in _PRE:
        rank = _PRE[word]
    elif word in {"p", "patch", "post", "pl"}:
        rank = 1
    elif len(word) == 1 and word != "x" and not m.group(3) and len(nums) >= 3:
        # OpenSSL-style letter releases: 1.1.1w > 1.1.1a > 1.1.1 (never "2.x", which is a wildcard)
        rank, num = 1, ord(word) - ord("a") + 1
    else:
        return None
    return nums, rank, num


def _pad(t: tuple[int, ...], n: int) -> tuple[int, ...]:
    return t + (0,) * (n - len(t))


def compare(a: str, b: str, scheme: str | None = None) -> int | None:
    if not a or not b or a.strip() in {"*", "-", "n/a"} or b.strip() in {"*", "-", "n/a"}:
        return None
    if scheme and scheme.lower() in UNSUPPORTED_SCHEMES:
        return None
    if looks_like_distro_version(a) or looks_like_distro_version(b):
        return None
    ka, kb = _key(a), _key(b)
    if ka is not None and kb is not None:
        n = max(len(ka[0]), len(kb[0]))
        ta, tb = (_pad(ka[0], n), ka[1], ka[2]), (_pad(kb[0], n), kb[1], kb[2])
        return (ta > tb) - (ta < tb)
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return None
    return (va > vb) - (va < vb)


def parse_simple_constraint(text: str) -> tuple[str, str] | None:
    """Parse a free-text ``'<= 2.0.1'`` / ``'< 3'`` statement. Anything more complex returns None."""
    m = re.match(r"^\s*(<=|<)\s*([\w.\-]+)\s*$", text or "")
    if not m or _key(m.group(2)) is None:
        return None
    return m.group(1), m.group(2)


# ------------------------------------------------------------------ distribution package versions
# Debian/Ubuntu (dpkg) and RPM have their own, well-defined ordering rules. These are used ONLY when a
# distribution's own advisory gives a fixed package version for the same distribution release.


def _deb_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a: str, b: str) -> int:
    """dpkg's verrevcmp for one part (upstream version or revision)."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < len(a) else 0
            bc = _deb_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _deb_split(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def compare_deb(a: str, b: str) -> int | None:
    """Compare two Debian/Ubuntu package versions (epoch:upstream-revision). None if malformed."""
    try:
        ea, ua, ra = _deb_split(a.strip())
        eb, ub, rb = _deb_split(b.strip())
    except ValueError:
        return None
    if not ua or not ub:
        return None
    if ea != eb:
        return (ea > eb) - (ea < eb)
    c = _deb_part(ua, ub) or _deb_part(ra, rb)
    return (c > 0) - (c < 0)


def _rpm_segment_cmp(a: str, b: str) -> int:
    """rpmvercmp: compare alternating numeric/alpha segments; '~' sorts before anything, '^' after."""
    import re as _re
    while a or b:
        a = _re.sub(r"^[^A-Za-z0-9~^]+", "", a)
        b = _re.sub(r"^[^A-Za-z0-9~^]+", "", b)
        if a.startswith("~") or b.startswith("~"):
            if not a.startswith("~"):
                return 1
            if not b.startswith("~"):
                return -1
            a, b = a[1:], b[1:]
            continue
        if a.startswith("^") or b.startswith("^"):
            if not a:
                return -1
            if not b:
                return 1
            if not a.startswith("^"):
                return 1
            if not b.startswith("^"):
                return -1
            a, b = a[1:], b[1:]
            continue
        if not a or not b:
            break
        num = a[0].isdigit()
        ma = _re.match(r"^\d+" if num else r"^[A-Za-z]+", a)
        mb = _re.match(r"^\d+" if num else r"^[A-Za-z]+", b)
        sa = ma.group(0) if ma else ""
        sb = mb.group(0) if mb else ""
        if not sb:
            return 1 if num else -1
        if num:
            ia, ib = int(sa), int(sb)
            if ia != ib:
                return 1 if ia > ib else -1
        elif sa != sb:
            return 1 if sa > sb else -1
        a, b = a[len(sa):], b[len(sb):]
    if not a and not b:
        return 0
    return 1 if a else -1


def compare_rpm(a: str, b: str) -> int | None:
    """Compare RPM epoch:version-release strings (no package name). None if malformed."""
    def split(v: str) -> tuple[int, str, str]:
        epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        version, _, release = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch or 0), version, release
    try:
        ea, va, ra = split(a.strip())
        eb, vb, rb = split(b.strip())
    except ValueError:
        return None
    if not va or not vb:
        return None
    if ea != eb:
        return 1 if ea > eb else -1
    return _rpm_segment_cmp(va, vb) or _rpm_segment_cmp(ra, rb)

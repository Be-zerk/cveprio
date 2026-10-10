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

"""Debian/Ubuntu and RPM version ordering (reference cases from dpkg and rpm behaviour)."""

import pytest

from cveprio.versions import compare_deb, compare_rpm


@pytest.mark.parametrize("a,b,expected", [
    ("1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.3", 1),   # the demo case: newer than Ubuntu's fixed build
    ("1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.3", 0),
    ("1:9.6p1-3ubuntu13", "1:9.6p1-3ubuntu13.3", -1),
    ("1.0~rc1-1", "1.0-1", -1),                           # tilde sorts before anything
    ("1.0-1", "1.0+b1-1", -1),
    ("2:1.0-1", "1:9.9-1", 1),                            # epoch wins
    ("1.0-1ubuntu1", "1.0-1", 1),
    ("8.9p1-3ubuntu0.10", "8.9p1-3ubuntu0.9", 1),         # numeric, not string, comparison
    ("1.2.3", "1.2.3-0", 0),                              # missing revision equals "0"
])
def test_compare_deb(a, b, expected):
    got = compare_deb(a, b)
    assert got is not None and (got > 0) - (got < 0) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("0:8.7p1-38.el9_4.1", "0:8.7p1-38.el9_4.1", 0),
    ("0:8.7p1-38.el9_4.4", "0:8.7p1-38.el9_4.1", 1),
    ("0:8.7p1-34.el9", "0:8.7p1-38.el9_4.1", -1),
    ("1.0~rc1-1", "1.0-1", -1),
    ("1:1.0-1", "0:9.0-1", 1),
    ("1.0a-1", "1.0-1", 1),
    ("2.10-1", "2.9-1", 1),
    ("1.0^git1-1", "1.0-1", 1),                            # caret sorts after the base version
])
def test_compare_rpm(a, b, expected):
    assert compare_rpm(a, b) == expected

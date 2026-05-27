import pytest

from tocode.cli import parse_jobs


def test_parse_jobs_accepts_auto_and_positive_ints() -> None:
    assert parse_jobs("auto") is None
    assert parse_jobs("3") == 3


def test_parse_jobs_rejects_zero() -> None:
    with pytest.raises(Exception):
        parse_jobs("0")

import pytest

from tocode.cli import build_parser, parse_jobs


def test_parse_jobs_accepts_auto_and_positive_ints() -> None:
    assert parse_jobs("auto") is None
    assert parse_jobs("3") == 3


def test_parse_jobs_rejects_zero() -> None:
    with pytest.raises(Exception):
        parse_jobs("0")


def test_parser_uses_tree_as_opt_in_flag() -> None:
    parser = build_parser()

    default_args = parser.parse_args(["sample.bin"])
    tree_args = parser.parse_args(["--tree", "sample.bin"])

    assert default_args.tree is False
    assert tree_args.tree is True


def test_parser_accepts_short_quiet_flag() -> None:
    args = build_parser().parse_args(["-q", "sample.bin"])

    assert args.quiet is True

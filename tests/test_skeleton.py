import pytest

from domain_suffixes.skeleton import get_tld, main

__author__ = "John Conwell"
__copyright__ = "John Conwell"
__license__ = "MIT"


def test_get_tld():
    """API Tests"""
    assert get_tld("stuff.com") == "com"
    assert get_tld("stuff.co.uk") == "co.uk"
    assert get_tld("stuff.nottld") is None


def test_main(capsys):
    """CLI Tests"""
    # capsys is a pytest fixture that allows asserts against stdout/stderr
    # https://docs.pytest.org/en/stable/capture.html
    main(["stuff.com"])
    captured = capsys.readouterr()
    assert "com" in captured.out

import re

from sanitary import Sanitizer


def test_key_patterns_match_substring_of_key_name():
    data = {
        "secret": "a",
        "aws_secret_access_key": "b",
        "session_token": "c",
        "username": "safe",
    }

    cleaned = Sanitizer(key_patterns={r"secret", r"token"}).sanitize(data)

    assert cleaned == {
        "secret": "********",
        "aws_secret_access_key": "********",
        "session_token": "********",
        "username": "safe",
    }


def test_key_patterns_support_regex_anchors():
    data = {"refresh_token": "a", "token_count": 3, "tokenizer": "safe"}

    # Only keys *ending* in `_token` are masked.
    cleaned = Sanitizer(key_patterns={re.compile(r"_token$")}).sanitize(data)

    assert cleaned == {"refresh_token": "********", "token_count": 3, "tokenizer": "safe"}


def test_key_patterns_recurse_into_nested_structures():
    data = {"outer": {"api_secret": "x", "note": "keep"}, "items": [{"user_token": "y"}]}

    cleaned = Sanitizer(key_patterns={r"secret", r"token"}).sanitize(data)

    assert cleaned == {
        "outer": {"api_secret": "********", "note": "keep"},
        "items": [{"user_token": "********"}],
    }


def test_key_patterns_combine_with_exact_keys():
    data = {"password": "p", "github_token": "t", "name": "safe"}

    cleaned = Sanitizer(keys={"password"}, key_patterns={r"token"}).sanitize(data)

    assert cleaned == {"password": "********", "github_token": "********", "name": "safe"}


def test_key_patterns_are_case_sensitive_unless_flagged():
    data = {"SECRET": "a", "secret": "b"}

    # Without a flag, the uppercase key is not matched...
    assert Sanitizer(key_patterns={r"secret"}).sanitize(data) == {
        "SECRET": "a",
        "secret": "********",
    }
    # ...but an inline (?i) makes it case-insensitive.
    assert Sanitizer(key_patterns={r"(?i)secret"}).sanitize(data) == {
        "SECRET": "********",
        "secret": "********",
    }


def test_key_patterns_match_only_key_names_not_values():
    # A value that contains "token" is not masked unless its key matches.
    data = {"description": "this mentions a token"}

    cleaned = Sanitizer(key_patterns={r"token"}).sanitize(data)

    assert cleaned == {"description": "this mentions a token"}

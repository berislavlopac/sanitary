import hashlib

import pytest

from sanitary import Sanitizer


def _expected_hash(value, hash_algo):
    hash_function = getattr(hashlib, hash_algo)
    hashed = hash_function(value.encode())
    try:
        return hashed.hexdigest()
    except TypeError:
        return hashed.hexdigest(256)


@pytest.mark.parametrize("hash_algo", hashlib.algorithms_guaranteed)
def test_sensitive_data_is_hashed(hash_algo):
    data = {
        "email": "user@domain.xyz",
        "password": "this is a sensitive value",
        "safe_value": "this is not sensitive",
    }

    sanitizer = Sanitizer(keys={"email", "password"}, replacement=getattr(hashlib, hash_algo))
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data["safe_value"] == data["safe_value"]
    assert cleaned_data["password"] == _expected_hash(data["password"], hash_algo)
    assert cleaned_data["email"] == _expected_hash(data["email"], hash_algo)


def test_sensitive_data_is_replaced_with_custom_callable():
    def replacement_callable(value):
        return "foo bar baz"

    data = {
        "email": "user@domain.xyz",
        "password": "this is a sensitive value",
        "safe_value": "this is not sensitive",
    }

    sanitizer = Sanitizer(keys={"email", "password"}, replacement=replacement_callable)
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data["safe_value"] == data["safe_value"]
    assert cleaned_data["password"] == "foo bar baz"
    assert cleaned_data["email"] == "foo bar baz"

import pytest

from sanitary import Sanitizer

SENSITIVE_PATTERNS = {
    r"""'Authentication':""",
    r""""Authentication":""",
    r"""'Refresh':""",
    r""""Refresh":""",
    r"Bearer ",
}


@pytest.mark.parametrize(
    "message",
    (
        """{\n"textPayload": "Response Headers: {'Authentication': 'Bearer sensitive_info_auth_token',\n'Refresh': 'sensitive_info_refresh_token'}",\n}""",
        """some random text 'Bearer sensitive_info_auth_token'""",
        """{'Refresh': 'sensitive_info_refresh_token'}""",
    ),
)
def test_text_is_cleaned_correctly(message):
    clean_message = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(message)
    assert clean_message.startswith("#### WARNING:")


def test_text_in_structure_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "request_type": "http",
        "event": "some random text 'Bearer sensitive_info_auth_token'",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    assert cleaned_data["event"].startswith("#### WARNING:")
    assert cleaned_data["request_type"] == "http"
    assert cleaned_data["context_id"] == "cxt_fe76c000000000000000000_0000000000000"


def test_textual_value_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "str_field": "Bearer sensitive_info_auth_token",
        "event": "some random text",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    assert cleaned_data["str_field"].startswith("#### WARNING:")
    assert cleaned_data["context_id"] == "cxt_fe76c000000000000000000_0000000000000"
    assert cleaned_data["event"] == "some random text"


def test_list_value_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "list_field": ["http", "Bearer sensitive_info_auth_token", "blabla"],
        "event": "some random text",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    assert cleaned_data["list_field"][0] == "http"
    assert cleaned_data["list_field"][1].startswith("#### WARNING:")
    assert cleaned_data["list_field"][2] == "blabla"


def test_dict_value_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "dict_field": {"a": "http", "b": "Bearer sensitive_info_auth_token", "c": "blabla"},
        "event": "some random text",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    assert cleaned_data["dict_field"]["a"] == "http"
    assert cleaned_data["dict_field"]["b"].startswith("#### WARNING:")
    assert cleaned_data["dict_field"]["c"] == "blabla"


def test_tuple_value_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "tuple_field": ("http", "Bearer sensitive_info_auth_token", "blabla"),
        "event": "some random text",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    assert cleaned_data["tuple_field"][0] == "http"
    assert cleaned_data["tuple_field"][1].startswith("#### WARNING:")
    assert cleaned_data["tuple_field"][2] == "blabla"


def test_set_value_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "set_field": {"http", "Bearer sensitive_info_auth_token", "blabla"},
        "event": "some random text",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    cleaned_field = sorted(cleaned_data["set_field"])
    assert cleaned_field[0].startswith("#### WARNING:")
    assert cleaned_field[1] == "blabla"
    assert cleaned_field[2] == "http"


def test_object_without_dict_is_cleaned_correctly():
    class FooClass:
        __slots__ = []

        def __str__(self):
            return "Bearer sensitive_info_auth_token"

    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "object_field": FooClass(),
        "event": "some random text",
    }

    cleaned_data = Sanitizer(patterns=SENSITIVE_PATTERNS).sanitize(data)

    print(cleaned_data)

    assert isinstance(cleaned_data["object_field"], str)
    assert cleaned_data["object_field"].startswith("#### WARNING:")

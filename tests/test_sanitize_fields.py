from decimal import Decimal

from sanitary import Sanitizer

SENSITIVE_KEYS = {
    "password",
    "email",
    "email_1",
    "firstname",
    "lastname",
    "authentication",
    "refresh",
    "auth",
}


def test_sensitive_fields_are_cleaned():
    data = {
        "Email": "user@domain.xyz",
        "password": "this is a sensitive value",
    }

    sanitizer = Sanitizer(keys=SENSITIVE_KEYS)
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data == {
        "Email": "********",
        "password": "********",
    }


def test_sensitive_fields_are_cleaned_recursively():
    data = {
        "event": {
            "Email": "user@domain.xyz",
            "password": "this is a sensitive value",
        }
    }

    sanitizer = Sanitizer(keys=SENSITIVE_KEYS)
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data["event"]["password"] == "********"
    assert cleaned_data["event"]["Email"] == "********"


def test_setting_custom_sensitive_fields_cleans_output_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "illegalKey": "blabla",
    }

    sanitizer = Sanitizer(keys={"illegalkey", "foo"})
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data["illegalKey"] == "********"
    assert cleaned_data["context_id"] == "cxt_fe76c000000000000000000_0000000000000"


def test_complex_object_is_cleaned_correctly():
    data = {
        "context": {"email": "sensitive@email.address"},
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "parameters": {
            "context": {"callerUserId": None},
            "body": {"email": "sensitive@email.address", "password": "sensitive_password"},
        },
        "response": {
            "status": "OK",
            "auth": "eyJra...",
            "refresh": "eyJjd...",
            "email_1": "user@domain",
        },
        "Authentication": "eyJra...",
        "request_type": "http",
        "email": "sensitive@email.address",
        "password": "sensitive_value",
        "calling_user_type": "service",
        "event": "Request",
        "logger": "service_function.common.cloud_function",
        "level": "info",
        "timestamp": "2021-01-01T00:00:00.000000Z",
        "as_list": [
            {
                "firstName": "Sensitive First Name",
                "lastName": "Sensitive Last Name",
                "callerUserId": "000000000000",
            },
            {
                "firstName": "Sensitive First Name",
                "lastName": "Sensitive Last Name",
                "callerUserId": "000000000000",
            },
        ],
        "another_list": ["1", "2"],
    }

    sanitizer = Sanitizer(keys=SENSITIVE_KEYS)
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data is not None
    assert cleaned_data["email"] == "********"
    assert cleaned_data["password"] == "********"
    assert cleaned_data["parameters"]["body"]["email"] == "********"
    assert cleaned_data["parameters"]["body"]["password"] == "********"
    assert cleaned_data["as_list"][0]["firstName"] == "********"
    assert cleaned_data["as_list"][0]["lastName"] == "********"
    assert cleaned_data["as_list"][1]["firstName"] == "********"
    assert cleaned_data["as_list"][1]["lastName"] == "********"
    assert cleaned_data["context"]["email"] == "********"
    assert cleaned_data["response"]["auth"] == "********"
    assert cleaned_data["response"]["refresh"] == "********"
    assert cleaned_data["response"]["email_1"] == "********"
    assert cleaned_data["Authentication"] == "********"
    assert cleaned_data != data


def test_numeric_values_are_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "int_field": 123,
        "float_field": 123.45,
    }

    sanitizer = Sanitizer(keys=SENSITIVE_KEYS)
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data["int_field"] == 123
    assert cleaned_data["float_field"] == 123.45


def test_decimal_value_is_cleaned_correctly():
    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "decimal_field": Decimal("123.45"),
        "event": "some random text",
    }

    sanitizer = Sanitizer(keys=SENSITIVE_KEYS)
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data["decimal_field"] == 123.45


def test_generic_object_is_cleaned_correctly():
    class FooClass:
        def __init__(self):
            self.foo = "this is not sensitive"
            self.sensitive = "this is sensitive data"

    data = {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "object_field": FooClass(),
        "event": "some random text",
    }

    sanitizer = Sanitizer(keys={"sensitive"})
    cleaned_data = sanitizer.sanitize(data)

    assert cleaned_data == {
        "context_id": "cxt_fe76c000000000000000000_0000000000000",
        "event": "some random text",
        "object_field": {"foo": "this is not sensitive", "sensitive": "********"},
    }


class MyCustomClass:
    def __init__(self):
        self.foo = "this is not sensitive"
        self.sensitive = "this is sensitive data"

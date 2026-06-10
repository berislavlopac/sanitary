import pytest

from sanitary import Sanitizer


class Document:
    """An object that narrows itself to a safe, renamed subset of its fields."""

    def __init__(self):
        self.id = "doc-123"
        self.title = "Some bulky title"
        self.body = "Free text that should never be logged"
        self.secret = "s3cr3t"

    def __sanitary_context__(self):
        return {"document_id": self.id, "secret": self.secret}


def test_sanitary_context_method_narrows_and_is_sanitized():
    cleaned = Sanitizer(keys={"secret"}).sanitize(Document())

    # Only the hook's fields appear (body/title are dropped), and keys still apply.
    assert cleaned == {"document_id": "doc-123", "secret": "********"}


def test_sanitary_context_property_is_used():
    class Account:
        @property
        def __sanitary_context__(self):
            return {"user": "alice", "token": "abc123"}

    cleaned = Sanitizer(keys={"token"}).sanitize(Account())

    assert cleaned == {"user": "alice", "token": "********"}


def test_sanitary_context_dict_attribute_is_used():
    class Thing:
        def __init__(self):
            self.__sanitary_context__ = {"safe": "ok", "secret": "hide-me"}

    cleaned = Sanitizer(keys={"secret"}).sanitize(Thing())

    assert cleaned == {"safe": "ok", "secret": "********"}


def test_sanitary_context_is_honoured_in_deny_mode():
    cleaned = Sanitizer(keys={"secret"}, unknown_objects="deny").sanitize(Document())

    assert cleaned == {"document_id": "doc-123", "secret": "********"}


def test_deny_mode_redacts_hookless_object():
    class Leaky:
        def __init__(self):
            self.email = "user@example.com"
            self.note = "free text"

    cleaned = Sanitizer(unknown_objects="deny").sanitize(Leaky())

    assert cleaned == "********"


def test_vars_mode_walks_hookless_object_by_default():
    class Leaky:
        def __init__(self):
            self.note = "free text"
            self.secret = "hide-me"

    cleaned = Sanitizer(keys={"secret"}).sanitize(Leaky())

    assert cleaned == {"note": "free text", "secret": "********"}


def test_invalid_unknown_objects_raises():
    with pytest.raises(ValueError, match="unknown_objects"):
        Sanitizer(unknown_objects="nonsense")

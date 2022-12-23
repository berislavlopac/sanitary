import json
import logging

import pytest
import structlog

from sanitary import StructlogSanitizer

SENSITIVE_KEYS = {"email", "password"}


@pytest.fixture(autouse=True)
def get_logger():
    logging.getLogger().setLevel(level=logging.INFO)

    def _get_logger(name, sanitizer):
        structlog.configure(
            processors=[sanitizer, structlog.processors.JSONRenderer()],
            logger_factory=structlog.stdlib.LoggerFactory(),
        )

        return structlog.stdlib.get_logger(name).bind()

    return _get_logger


def test_message_with_password_and_email_is_cleaned_correctly(get_logger, caplog):
    message = "Test with request password"
    logger_name = "test logger"

    logger = get_logger(logger_name, StructlogSanitizer(keys=SENSITIVE_KEYS))
    request = {
        "Email": "user@domain.xyz",
        "password": "this is a sensitive value",
    }

    logger.info(message, request=request)

    record = json.loads(caplog.messages[0])
    assert record["request"]["password"] == "********"
    assert record["request"]["Email"] == "********"


def test_message_with_password_and_email_in_event_is_cleaned_correctly(get_logger, caplog):
    logger_name = "test logger"
    message = {
        "email": "user@domain.xyz",
        "password": "this is a sensitive value",
    }

    logger = get_logger(logger_name, StructlogSanitizer(keys=SENSITIVE_KEYS))
    logger.info(message)

    record = json.loads(caplog.messages[0])
    assert record["event"]["password"] == "********"
    assert record["event"]["email"] == "********"

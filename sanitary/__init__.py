# SPDX-FileCopyrightText: 2022-present Berislav Lopac <berislav@lopac.net>
#
# SPDX-License-Identifier: MIT

"""Custom processor for cleaning sensitive data."""
from __future__ import annotations

import hashlib
import json
import re
from collections import ChainMap
from decimal import Decimal
from functools import singledispatchmethod
from typing import Any, AnyStr, cast, Iterable, Pattern, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from structlog.types import EventDict, WrappedLogger

from .hashing import HASHLIB_FUNCTIONS, HashObjectProtocol, ReplacementType


class Sanitizer:
    """
    Base class for sensitive data sanitizers.

    Args:
        keys: Collection of keys to sanitize. Will be normalized to lowercase.
        patterns: Collection of regular expression patterns; will be compiled using
                  `re.compile`.
        replacement: A string or callable to be used to replace the value. A callable must
                     either accept and return a `str` value, or accept a `bytes` object
                     and return an object compatible with the `hashlib` function.
        message: The text to replace the matching string patterns.
    """

    def __init__(
        self,
        *,
        keys: Iterable[str] = (),
        patterns: Iterable[Pattern[AnyStr]] = (),
        replacement: ReplacementType = "********",
        message: str = "#### WARNING: Message replaced due to sensitive information.",
    ):
        self.replacement: ReplacementType = replacement
        self.keys: Set = set(map(str.lower, keys))
        self.patterns: Set[Pattern[AnyStr]] = set(map(re.compile, patterns))  # type: ignore
        self.message: str = message

    @singledispatchmethod
    def sanitize(self, data: Any) -> Any:
        """
        Sanitize data by masking potentially sensitive information.

        If an unknown data type is encountered, its string
        representation will be sanitized.

        Args:
            data: The data to sanitize.

        Returns:
            The sanitized form of data.
        """
        try:
            data = vars(data)
        except TypeError:
            data = str(data)
        return self.sanitize(data)

    @sanitize.register(float)
    @sanitize.register(int)
    def _sanitize_number(self, data):
        return data

    @sanitize.register
    def _sanitize_decimal(self, data: Decimal):
        return float(data)

    @sanitize.register
    def _sanitize_str(self, data: str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            for sensitive_pattern in self.patterns:
                if sensitive_pattern.search(data):  # type: ignore
                    return self.message
            return data
        else:
            return self.sanitize(data)

    @sanitize.register(set)
    @sanitize.register(tuple)
    @sanitize.register(list)
    def _sanitize_sequence(self, data):
        return [self.sanitize(value) for value in data]

    @sanitize.register
    def _sanitize_dict(self, data: dict):
        sensitive_fields = {field.lower() for field in self.keys}
        cleaned_data = ChainMap({}, data)
        for key, value in cleaned_data.items():
            cleaned_data[key] = (
                _replace(value, self.replacement)
                if key.lower() in sensitive_fields
                else self.sanitize(value)
            )
        return dict(cleaned_data)


def _replace(value: Any, replacement: ReplacementType):
    if callable(replacement):
        value = str(value)
        if replacement in HASHLIB_FUNCTIONS:
            replaced = cast(HashObjectProtocol, replacement(value.encode()))
            if replacement in (hashlib.shake_128, hashlib.shake_256):
                return replaced.hexdigest(256)
            return replaced.hexdigest()
        return replacement(value)
    return replacement


class StructlogSanitizer(Sanitizer):
    """Structlog processor for cleaning up logging context by masking sensitive data."""

    def __call__(self, logger: WrappedLogger, name: str, event_dict: EventDict) -> EventDict:
        """
        Makes the sanitizer a callable, compatible with the Structlog processor API.

        For details see https://www.structlog.org/en/stable/processors.html

        Args:
            logger: The logger instance doing the logging.
            name: Name of the logging method, e.g. `info` or `warning`.
            event_dict: Current context, including modifications by other processors.

        Returns:
            dict
        """
        return self.sanitize(event_dict)

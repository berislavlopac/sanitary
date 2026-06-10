# SPDX-FileCopyrightText: 2022-present Berislav Lopac <berislav@lopac.net>
#
# SPDX-License-Identifier: MIT

"""Custom processor for cleaning sensitive data."""

from __future__ import annotations

import hashlib
import json
import re
from collections import ChainMap
from collections.abc import Iterable
from decimal import Decimal
from functools import singledispatchmethod
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version
from re import Pattern
from typing import TYPE_CHECKING, Any, AnyStr, Literal, cast

if TYPE_CHECKING:
    from structlog.types import EventDict, WrappedLogger

from .hashing import HASHLIB_FUNCTIONS, HashObjectProtocol, ReplacementType

try:
    __version__ = _version("sanitary")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"


#: Hook an object can expose to declare its own safe representation. It may be a
#: `dict` (or `Mapping`), or a callable/property returning one; that value is
#: sanitized in place of the object's attributes. Lets a class select and rename
#: the fields that are safe to expose, e.g. `id` -> `document_id`.
SANITARY_CONTEXT = "__sanitary_context__"

#: How `Sanitizer` handles an unknown object that does not expose `SANITARY_CONTEXT`.
UnknownObjects = Literal["vars", "deny"]


class Sanitizer:
    """
    Base class for sensitive data sanitizers.

    Args:
        keys: Collection of keys to sanitize, matched by exact name (case-insensitively).
              Will be normalized to lowercase.
        patterns: Collection of regular expression patterns; will be compiled using
                  `re.compile`. Matched against string *values*.
        key_patterns: Collection of regular expression patterns matched against *key
                      names* (compiled like `patterns`). A key whose name matches any of
                      them has its value replaced, letting a single rule cover many keys
                      (e.g. `secret` for `secret`, `aws_secret_access_key`, ...). Matched
                      against the key as written, so include `(?i)` for case-insensitivity.
        replacement: A string or callable to be used to replace the value. A callable must
                     either accept and return a `str` value, or accept a `bytes` object
                     and return an object compatible with the `hashlib` function.
        message: The text to replace the matching string patterns.
        unknown_objects: How to handle an object of an unknown type that does not expose
                         a `__sanitary_context__` hook. `"vars"` (the default) walks its
                         attributes via `vars()`, so every attribute whose name is not in
                         `keys` passes through. `"deny"` instead replaces the whole object
                         with `replacement`, so unrecognised objects are masked by default.
                         Scalars (`None`, numbers, strings) are not objects and always pass
                         through regardless of this setting.
                         An object exposing `__sanitary_context__` is always narrowed to
                         that representation regardless of this setting.

    Raises:
        ValueError: If `unknown_objects` is not `"vars"` or `"deny"`.
    """

    # All parameters are keyword-only public configuration options.
    def __init__(  # noqa: PLR0913
        self,
        *,
        keys: Iterable[str] = (),
        patterns: Iterable[Pattern[AnyStr]] = (),
        key_patterns: Iterable[Pattern[AnyStr]] = (),
        replacement: ReplacementType = "********",
        message: str = "#### WARNING: Message replaced due to sensitive information.",
        unknown_objects: UnknownObjects = "vars",
    ):
        if unknown_objects not in ("vars", "deny"):
            # Inline message; a custom exception class is overkill for one validation.
            raise ValueError(  # noqa: TRY003
                f"unknown_objects must be 'vars' or 'deny', not {unknown_objects!r}"
            )
        self.replacement: ReplacementType = replacement
        self.keys: set = set(map(str.lower, keys))
        self.patterns: set[Pattern[AnyStr]] = set(map(re.compile, patterns))  # type: ignore
        self.key_patterns: set[Pattern[AnyStr]] = set(map(re.compile, key_patterns))  # type: ignore
        self.message: str = message
        self.unknown_objects: UnknownObjects = unknown_objects

    @singledispatchmethod
    def sanitize(self, data: Any) -> Any:
        """
        Sanitize data by masking potentially sensitive information.

        If the object exposes a `__sanitary_context__` hook (a dict, or a
        callable/property returning one), that representation is sanitized instead of
        the object itself. Otherwise the object is handled according to the
        `unknown_objects` setting: walked via `vars()` (default), or replaced wholesale
        when `unknown_objects="deny"`. An object with neither a `__dict__` nor a hook
        falls back to sanitizing its string representation.

        Args:
            data: The data to sanitize.

        Returns:
            The sanitized form of data.
        """
        context = getattr(data, SANITARY_CONTEXT, None)
        if context is not None:
            return self.sanitize(context() if callable(context) else context)
        if self.unknown_objects == "deny":
            return _replace(data, self.replacement)
        try:
            data = vars(data)
        except TypeError:
            data = str(data)
        return self.sanitize(data)

    @sanitize.register(float)
    @sanitize.register(int)
    def _sanitize_number(self, data):
        return data

    @sanitize.register(type(None))
    def _sanitize_none(self, data):
        # `None` is a scalar absence-of-value, not an unknown object, so it passes
        # through untouched in every mode. In particular `unknown_objects="deny"`
        # must not mask it: redacting `None` would imply a sensitive value was
        # present where there was none.
        return data

    @sanitize.register
    def _sanitize_decimal(self, data: Decimal):
        return float(data)

    @sanitize.register
    def _sanitize_str(self, data: str):
        # Only attempt to parse strings that plausibly hold a JSON object or array, so
        # that real JSON structures are still walked while plain text (the common case at
        # high log volume) skips the parse cost and goes straight to pattern matching.
        if data.strip().startswith(("{", "[")):
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError:
                pass
            else:
                return self.sanitize(parsed)
        for sensitive_pattern in self.patterns:
            if sensitive_pattern.search(data):  # type: ignore
                return self.message
        return data

    @sanitize.register(set)
    @sanitize.register(tuple)
    @sanitize.register(list)
    def _sanitize_sequence(self, data):
        return [self.sanitize(value) for value in data]

    @sanitize.register
    def _sanitize_dict(self, data: dict):
        cleaned_data = ChainMap({}, data)
        for key, value in cleaned_data.items():
            cleaned_data[key] = (
                _replace(value, self.replacement)
                if self._is_sensitive_key(key)
                else self.sanitize(value)
            )
        return dict(cleaned_data)

    def _is_sensitive_key(self, key: str) -> bool:
        if key.lower() in self.keys:
            return True
        return any(pattern.search(key) for pattern in self.key_patterns)  # type: ignore


def _replace(value: Any, replacement: ReplacementType):
    if callable(replacement):
        value = str(value)
        if replacement in HASHLIB_FUNCTIONS:
            replaced = cast(HashObjectProtocol, replacement(value.encode()))  # type: ignore
            if replacement in (hashlib.shake_128, hashlib.shake_256):
                return replaced.hexdigest(256)
            return replaced.hexdigest()
        return replacement(value)  # type: ignore
    return replacement


class StructlogSanitizer(Sanitizer):
    """Structlog processor for cleaning up logging context by masking sensitive data."""

    def __call__(self, logger: WrappedLogger, name: str, event_dict: EventDict) -> EventDict:  # noqa: F841
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

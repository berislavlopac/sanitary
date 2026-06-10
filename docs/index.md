# Sanitary

Sanitary is a simple utility that can remove/mask sensitive information, such as PII, from any data structure. It also includes a Structlog-compatible [processor](https://www.structlog.org/en/stable/processors.html) to clean up structured log messages.

It will automatically mask information marked as sensitive. By default, the masked data is replaced by a generic string, which can be configured to use a hashing function instead.

## Installation

Sanitizer needs to be installed like any other Python package:

```shell
> pip install sanitary
```

## Base Usage

The first step is to instantiate a `Sanitizer` object:

```python
>>> from sanitary import Sanitizer
>>> sanitizer = Sanitizer(keys={"foo", "bar"})
>>> sanitizer.sanitize({"foo": 123, "bar": "abc", "baz": "boom"})
{"foo": "********", "bar": "********", "baz": "boom"}
```

### Configuration

The `Sanitizer` class accepts the following arguments:

* `keys`: An iterator of key names that will be searched for recursively. Any of these keys will have its value replaced by the replacement value.
* `patterns`: An iterator of regular expression patterns that will be used to search the textual values. A value that matches any of the patterns will be entirely replaced by the message value.
* `key_patterns`: An iterator of regular expression patterns matched against *key names* (the key-name analogue of `patterns`). Any key whose name matches has its value replaced by the replacement value, so a single rule can cover many related keys. See [Matching Keys by Pattern](#matching-keys-by-pattern).
* `replacement`: Can be any of the following types of values:
    1. A plain text, which will simply replace the sensitive value.
    2. A callable which takes a string as its single argument and returns another string, which will replace the value.
    3. A callable which takes a bytes object as its single argument and returns a "hash object"; this allows using the [`hashlib`](https://docs.python.org/3/library/hashlib.html) functions to mask the data. 
* `message`: The textual message which will replace the value that matches any of the defined patterns.
* `unknown_objects`: How to handle an object of an unrecognised type that does not expose a `__sanitary_context__` hook — `"vars"` (the default) walks its attributes, or `"deny"` replaces the whole object with the replacement value. See [Arbitrary Objects](#arbitrary-objects).


## Data Hashing

If the `replacement` argument is a callable, the value of a corresponding sensitive key will be replaced with the return value of the callable (or its `hexdigest`). This way, the sanitized data can still be tracked (e.g. an email address will always have the same hash value) without exposing the actual value.

```python
>>> import hashlib
>>> from sanitary import Sanitizer
>>> sanitizer = Sanitizer(keys={"password", "email"}, replacement=hashlib.sha256)
>>> sanitizer.sanitize({"event": "clean password", "password": "blabla", "foo": {"Email": "test@example.com"}})
{
    'event': 'clean password',
    'password': 'ccadd99b16cd3d200c22d6db45d8b6630ef3d936767127347ec8a76ab992c2ea',
    'foo': {'Email': '973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b'}
}
>>>
```

## Sensitive Text Values

Sanitizer can also clean up any text values that match specific regular expression patterns; any such value is completely replaced with a hardcoded warning message.

```python
>>> from sanitary import Sanitizer
>>> sanitizer = Sanitizer(patterns={r"""'Authentication':"""})
>>> sanitizer.sanitize("'Authentication': 1234")
'#### WARNING: Message replaced due to sensitive information.'
>>> sanitizer.sanitize({"example": "'Authentication': 1234"})
{'example': '#### WARNING: Message replaced due to sensitive information.'}
>>>
```

## Matching Keys by Pattern

While `keys` matches **key names exactly** (case-insensitively), `key_patterns` matches
key names by regular expression — the key-name analogue of `patterns`. This lets a
single rule cover a whole family of related keys instead of enumerating every variant,
and (like `keys`) it recurses into nested structures:

```python
>>> from sanitary import Sanitizer
>>> sanitizer = Sanitizer(key_patterns={r"secret", r"token"})
>>> sanitizer.sanitize({"aws_secret_access_key": "x", "refresh_token": "y", "username": "safe"})
{'aws_secret_access_key': '********', 'refresh_token': '********', 'username': 'safe'}
```

Patterns are matched against the key name as written, so add an inline `(?i)` flag (or
compile with `re.IGNORECASE`) if you need case-insensitive matching, and anchor the
pattern (e.g. `r"_token$"`) to avoid over-matching. `key_patterns` only ever inspects
key *names*; a matching string appearing in a *value* is left alone unless its own key
matches.

## JSON-Encoded Values

Sometimes a structure is stored or logged as a JSON string rather than as a native
object. When a string value looks like a JSON object or array — i.e. it starts with
`{` or `[` after stripping whitespace — Sanitizer parses it and sanitizes the
decoded structure, so sensitive data hidden inside a serialized blob is still masked.

```python
>>> from sanitary import Sanitizer
>>> sanitizer = Sanitizer(keys={"password"})
>>> sanitizer.sanitize({"body": '{"password": "hunter2", "user": "alice"}'})
{'body': {'password': '********', 'user': 'alice'}}
```

Any other string is left untouched (apart from pattern matching against its value).
In particular, strings that merely *look* like JSON scalars are **not** parsed, so
their type is preserved:

```python
>>> sanitizer.sanitize("12345")
'12345'
>>> sanitizer.sanitize("true")
'true'
```

## Arbitrary Objects

When Sanitizer encounters an object of a type it does not otherwise recognise, by
default it walks the object's attributes (via `vars()`) and sanitizes them like a
dictionary. This means any attribute whose *name* is not in `keys` passes through —
including bulky or sensitive content under innocuous names.

An object can take control of its own representation by exposing a
`__sanitary_context__` hook — a `dict` (or a callable/property returning one) of the
fields that are safe to expose. When present, Sanitizer sanitizes that mapping instead
of the object's raw attributes, letting the class both *select* and *rename* fields:

```python
>>> from sanitary import Sanitizer
>>> class Document:
...     def __init__(self):
...         self.id = "doc-123"
...         self.body = "free text that should not be logged"
...         self.secret = "s3cr3t"
...     def __sanitary_context__(self):
...         return {"document_id": self.id, "secret": self.secret}
>>> Sanitizer(keys={"secret"}).sanitize(Document())
{'document_id': 'doc-123', 'secret': '********'}
```

For defence in depth, the `unknown_objects` argument controls what happens to an object
that does *not* expose the hook. The default, `"vars"`, walks its attributes as described
above. `"deny"` instead replaces any such object wholesale with the `replacement` value,
so unrecognised objects are masked by default rather than relying on every attribute name
being on the `keys` denylist:

```python
>>> class Plain:
...     def __init__(self):
...         self.note = "ok"
...         self.password = "hunter2"
>>> Sanitizer(unknown_objects="deny").sanitize(Plain())
'********'
```

Objects exposing `__sanitary_context__` are always narrowed to that representation,
regardless of the `unknown_objects` setting.

## Structlog Processor

The special subclass, `StructlogSanitizer`, is provided to enable sanitizing the logging context managed by the [`structlog`](https://www.structlog.org) library. It needs to be instantiated and added to the list of configured [processors](https://www.structlog.org/en/stable/processors.html):

```python
import hashlib
import structlog
from sanitary import StructlogSanitizer

structlog.configure(
    processors=[
        StructlogSanitizer(keys={"foo", "bar", "baz"}, replacement=hashlib.sha256), 
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
```

*[PII]: Personally Identifiable Information

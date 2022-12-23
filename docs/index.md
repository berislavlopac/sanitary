# Sanitary

Sanitary is a simple utility that can remove/mask sensitive information, such as PII, from any data structure. It also includes a Structlog-compatible [processor](https://www.structlog.org/en/stable/processors.html) to clean up structured log messages.

It will automatically mask sensitive information such as PII, login credentials and the like. By default, the masked data is replaced by a generic string, which can be configured to use a hashing function instead.

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
* `replacement`: Can be any of the following types of values:
    1. A plain text, which will simply replace the sensitive value.
    2. A callable which takes a string as its single argument and returns another string, which will replace the value.
    3. A callable which takes a bytes object as its single argument and returns a "hash object"; this allows using the [`hashlib`](https://docs.python.org/3/library/hashlib.html) functions to mask the data. 
* `message`: The textual message which will replace the value that matches any of the defined patterns.


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
"#### WARNING: Message replaced due to sensitive pattern: 'Authentication':"
>>> sanitizer.sanitize({"example": "'Authentication': 1234"})
{'example': "#### WARNING: Message replaced due to sensitive pattern: 'Authentication':"}
>>>
```

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

# Sanitary

[![PyPI - Version](https://img.shields.io/pypi/v/sanitary.svg)](https://pypi.org/project/sanitary)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sanitary.svg)](https://pypi.org/project/sanitary)

Sanitary is a utility for removing or replacing sensitive data from data structures.
It walks any nested structure and masks values by key name or by matching string
patterns; values can be replaced with a placeholder or a stable hash. It also ships
a `structlog`-compatible processor (`StructlogSanitizer`) for redacting log context,
and lets objects declare a safe representation via a `__sanitary_context__` hook.

## Installation

```console
pip install sanitary
```

## Documentation

Full documentation — usage, configuration, hashing, JSON handling, object narrowing,
and the `structlog` processor — is at
[sanitary.readthedocs.io](https://sanitary.readthedocs.io).

## License

`sanitary` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased changes are kept as news fragments in `release-notes/` and collated
into a dated section by `towncrier` at release time — see `just release`.

<!-- towncrier release notes start -->

## [0.2.0] - 2026-06-11

### Breaking Changes

- `Sanitizer` only attempts `json.loads` on string values that start with `{` or `[` after stripping, instead of on every string; JSON objects/arrays are still walked, but bare JSON scalar strings (e.g. `"123"`) are no longer coerced to their parsed types. (#2)

### Added

- Objects can expose a `__sanitary_context__` hook (a dict, or a callable/property returning one) to declare a safe, renamed subset of their fields, which is sanitized instead of their raw attributes. A new `unknown_objects="vars"|"deny"` argument additionally lets hookless unknown objects be masked wholesale (`"deny"`) instead of walked via `vars()` (`"vars"`, the default). (#1)
- New `key_patterns` argument: regular expressions matched against *key names* (the key-name analogue of `patterns`), so a single rule like `secret` can mask `secret`, `aws_secret_access_key`, ... without enumerating every variant. `keys` keeps its exact-match behaviour. (#3)
- Add support for Python 3.14 (now covered by the test matrix and the package classifiers).
- `sanitary.__version__` now exposes the installed package version (read from the package metadata via `importlib.metadata`).


## [0.1.0] - 2025-05-18

### Added

- use of uv for project management

### Changed

- use of ruff and deptry for code checks

## [0.0.1] - 2022-12-23

### Added

- initial release
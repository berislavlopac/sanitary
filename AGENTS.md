# AGENTS.md

Guidance for AI agents (and humans) working on **sanitary**. Complements
`README.md` and the docs under `docs/`. This file is about *how to work in this
repo* — conventions, commands, and the public contract that must not break.

## What this is

sanitary is a small utility for **removing or masking sensitive data** (PII,
credentials) from arbitrary data structures, plus a `structlog`-compatible
processor for redacting structured log context. Given a set of key names and/or
value regex patterns, it walks any nested structure and replaces matching data
with a placeholder (or a hash, for trackable-but-masked values).

It is a **library**, imported by other projects (e.g. `unclogger`). Treat the
public API as a contract — it changes only deliberately, with a `CHANGELOG.md`
entry.

### Keep it dependency-free

sanitary has **zero runtime dependencies** (`dependencies = []`). `structlog` is
only a *test* dependency, and `StructlogSanitizer` imports its types under
`TYPE_CHECKING` so the runtime import stays optional. **Do not add a runtime
dependency** (including making `structlog` a hard dependency) without a very
deliberate decision — staying dependency-free is a feature of this library.

## Layout

- `sanitary/__init__.py` — the whole public surface: `Sanitizer` (a
  `singledispatchmethod`-based recursive walker over dict/list/str/scalars) and
  its `structlog` subclass `StructlogSanitizer`.
- `sanitary/hashing.py` — `HASHLIB_FUNCTIONS`, `HashObjectProtocol`,
  `ReplacementType` (the replacement/hashing machinery).
- `sanitary/py.typed` — ships type information; keep it.
- `tests/` — pytest suite. `docs/` — mkdocs source (also the PyPI long description).

## Public API (the contract)

`Sanitizer` and `StructlogSanitizer`, constructed with keyword-only
`keys` / `patterns` / `replacement` / `message`. Semantics that callers rely on:

- `keys` match **by exact name, case-insensitively** (not substring) and recurse
  into nested structures; matched values are replaced with `replacement`.
- `patterns` are regexes matched against **string values**; a match replaces the
  whole value with `message`.
- `replacement` may be a string or a callable (incl. a `hashlib` function, for
  trackable hashing).

Keep these behaviours stable; update `docs/` and `CHANGELOG.md` on any change.

## Environment & workflow

- **Python ≥ 3.10** (`requires-python = ">=3.10"`).
- **[`uv`](https://docs.astral.sh/uv/)** for environments/dependencies;
  **[`just`](https://just.systems/)** as the task runner. Run `just` for the list.
- **Always use the `just` recipe** rather than calling the tool directly.

| Recipe | Purpose |
|---|---|
| `just test` | Unit tests (`pytest --spec`). |
| `just test-cov` | Tests with coverage (floor is **90%**). |
| `just lint` | `deptry` + `ruff format --check` + `ruff check` + `pydocstyle`. |
| `just type` | `pyrefly` over `sanitary/`. |
| `just analyze` | `vulture` (dead code) + `radon` (maintainability). |
| `just check` | `lint` + `type` + `analyze` — the pre-push gate. |
| `just reformat` | Auto-fix format + import order (`[confirm]` recipe). |
| `just docs` / `just docs-build` | Serve / build the mkdocs site. |
| `just commits` | Commits since the last tag (for the changelog). |

Multi-version testing (py310–313) is via **tox** (config in `pyproject.toml`
under `[tool.tox]`, `uv-venv-lock-runner`). The pre-push quality gate is
`just check` + `just test`, or the full `tox` matrix.
CI is **GitHub Actions** (`.github/workflows/ci.yml`): on push to `main` and on
PRs it runs the `checks` env and the py310–313 test matrix via
`uvx --with tox-uv tox` — the same tox envs you run locally.

## Conventions

- **Type checker is `pyrefly`** (not mypy/pyright/ty). Config in `[tool.pyrefly]`
  (`project-includes = ["sanitary/"]`, `search-path = ["."]`). It honours
  `# type: ignore` comments.
- **`ruff` is linter + formatter**, line length **96**. The lint `select` set in
  `pyproject.toml` is the contract; don't disable rules without a `# noqa: <code>`
  and a reason. `F841` is delegated to `vulture` (the `external` list).
- **Docstrings: Google convention** (enforced by `pydocstyle`; `D105/D107/D212/D401`
  ignored). Markdown in docstrings, single backticks for inline code.
- Mark intentionally-unused names with `# noqa: F841` (so vulture ignores them),
  not by underscore-prefixing.
- ASCII-only in code (identifiers, strings, comments). Typographic characters
  (em-dashes, smart quotes) belong in docs and prose, not in code.

## Working conventions

- Small, focused commits. Lowercase imperative subject; optional body explaining
  the *why*, not the *what*.
- **No `Co-Authored-By` footer.**
- Branch names use only `-` as a separator, never `/`.
- On a long-running WIP branch, commit locally; don't push every commit (it
  spams CI and notifications).
- Keep PR descriptions scoped to the change - no "future work" / "next steps"
  section.
- Finish PR work with a neutral-reviewer pass over your own diff.
- Review comments detach on force-push/rebase - warn before rewriting history on
  a PR that already has feedback; prefer a merge.
- Stay on the task at hand - note an incidental or unrelated issue in one line
  and move on, rather than rabbit-holing into it.

## Docs

Docs live in `docs/` (mkdocs + Material + `mkapi`), hosted on readthedocs, and
`docs/index.md` doubles as the PyPI long description (`readme = "docs/index.md"`
in `pyproject.toml`). `docs/reference.md` autogenerates the API reference from
docstrings via `mkapi` `:::` directives, so keep docstrings accurate, and update
the usage examples in `docs/index.md` when behaviour changes.

## Related

`unclogger` (structured-logging wrapper, same author) consumes this library via
`add_processors(StructlogSanitizer(...))`; its docs use sanitary as the worked
example. Keep `StructlogSanitizer`'s processor signature compatible.
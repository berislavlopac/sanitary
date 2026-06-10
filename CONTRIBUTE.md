# Contribute to sanitary

> **This guide is for human contributors.** If you are an AI coding agent, read
> [`AGENTS.md`](AGENTS.md) instead — it carries the same project rules in a form aimed
> at agents.

Thanks for contributing! This guide covers everything you need to develop, test, and
release sanitary.

sanitary is a small, **dependency-free** library for removing or masking sensitive
data from arbitrary data structures, plus a `structlog`-compatible processor. Its
public API — `Sanitizer` and `StructlogSanitizer` — is treated as a contract, so
behaviour changes are made deliberately and always come with a news fragment (see
[Changelog](#changelog)) and a docs update.

## Development Environment

[uv](https://docs.astral.sh/uv/) is used for dependency and package management, and
[just](https://just.systems/) provides the development task runner. Python **3.10+**
is required. Prefer the `just` recipe over calling the underlying tool directly.

Install dependencies:

```shell
$ uv sync
```

### Code Validation

Run all checks (linting, type checking, static analysis):

```shell
$ just check
```

Individual checks:

```shell
$ just lint     # deptry + ruff format/check + pydocstyle
$ just type     # pyrefly static type analysis
$ just analyze  # vulture (dead code) + radon (maintainability)
```

### Running Tests

```shell
$ just test       # pytest --spec
$ just test-cov   # with coverage (floor is 90%)
```

Multi-version testing (py310–py314) runs via `tox`:

```shell
$ uvx --with tox-uv tox
```

### Reformatting

```shell
$ just reformat   # ruff format + import sorting (asks for confirmation)
```

## Conventions

- **Commits:** keep them small and focused, with a lowercase imperative subject
  (e.g. `add deny mode for unknown objects`) and an optional body explaining *why*.
  Don't add `Co-Authored-By` footers. Branch names separate words with `-`, never `/`.
- **Code:** `ruff` is both linter and formatter (line length 96); `pyrefly` checks
  types; docstrings follow the Google convention. Keep code ASCII-only (em-dashes and
  smart quotes belong in prose and docs, not in code). Suppress a lint rule only with
  an inline `# noqa: <code>` and a short reason.
- **Public API:** `Sanitizer` and `StructlogSanitizer` are a contract — any behaviour
  change needs a news fragment and a docs update, and the library stays **dependency
  free** (no runtime dependencies; `structlog` is a test-only dependency).

## Changelog

Changes are recorded as **news fragments** rather than by editing `CHANGELOG.md`
directly. Each change adds one file to `release-notes/`, named `<id>.<type>.md`,
containing a one-line description. `<type>` is the change category — `breaking`,
`added`, `changed`, `deprecated`, `removed`, `fixed`, `security` (see
[`release-notes/README.md`](release-notes/README.md) for what each means and how it
maps to a version bump). `<id>` defaults to a unique timestamp (no reference); pass a
PR/issue number to render a `(#42)` reference instead.

```shell
$ just news added       # -> release-notes/+<timestamp>.added.md (no reference)
$ just news fixed 42    # -> release-notes/42.fixed.md (renders "(#42)")
```

Preview how the collated changelog will look for a given version, and get a
recommended version derived from the pending fragments:

```shell
$ just changelog-draft 0.2.0
$ just suggest-version    # e.g. "0.1.0 -> 0.2.0  (minor: added)"
```

`towncrier` folds the fragments into a dated `CHANGELOG.md` section at release time
(see below). The date is stamped automatically when the release is cut, so fragments
never carry a date — you don't need to know the release date in advance.

## Releasing

The release version lives in **exactly one place: the git tag**. `pyproject.toml`
declares the version as `dynamic` and `hatch-vcs` derives it from the tag at build
time, so there is no version number to bump by hand. `sanitary.__version__` reads it
back at runtime.

To cut a release, state the version once:

```shell
$ just release 0.2.0
```

This recipe:

1. Runs `just check` and `just test` first. If anything fails it aborts here, so a
   broken tree produces no changelog, commit, or tag.
2. Runs `towncrier build` to collate the news fragments into a new
   `## [0.2.0] - <today>` section in `CHANGELOG.md` and delete the fragments.
3. Commits the changelog, creates the `0.2.0` tag, and pushes the commit and tag.

Pushing the tag triggers the release workflow (`.github/workflows/release.yml`),
which re-runs the checks and the full py310–py314 test matrix and — **only if they
pass** — builds the package, publishes it to PyPI via [trusted publishing][tp] (OIDC;
no stored token), and creates the GitHub release (notes are extracted from the new
changelog section). Ordinary pushes and pull requests run `.github/workflows/ci.yml`
(checks + matrix only); they never publish. Prereleases (e.g. `0.2.0rc1`) are detected
automatically and marked as such on GitHub.

[tp]: https://docs.pypi.org/trusted-publishers/

> Because the tag is created locally before CI runs, a CI failure leaves a tag that
> published nothing. To redo the release, delete the tag and try again:
>
> ```shell
> $ git push --delete origin 0.2.0 && git tag -d 0.2.0
> ```

## Documentation

The documentation lives in `docs/` (mkdocs + MaterialX + `mkapi`); `docs/index.md`
also doubles as the PyPI long description. Serve it locally or build the static site:

```shell
$ just docs        # serve with live reload
$ just docs-build  # build into the site/ directory
```

The online documentation is built and hosted on Read the Docs, configured in
`.readthedocs.yaml`.

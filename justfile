# List available recipes.
help:
    @just --list --unsorted

# Run unit tests.
test:
    uv run pytest --spec

# Run unit tests with coverage report.
test-cov:
    uv run pytest --cov --spec

# Run linting and formating checks.
lint:
    uv run deptry .
    uv run ruff format --check .
    uv run ruff check .
    uv run pydocstyle sanitary/

# Run static typing analysis.
type:
    uv run pyrefly check sanitary/

# Run security checks.
analyze:
    uvx vulture --min-confidence 100 sanitary/
    uvx radon mi --show --multi --min B sanitary/

# Run all checks.
check: lint type analyze

# Extract the latest commits
commits:
    git log $(git describe --tags --abbrev=0)..HEAD --oneline --no-decorate

# Add a news fragment: `just news added` (auto id) or `just news fixed 42` (issue ref).
news type id=('+' + datetime('%s')):
    uv run towncrier create --edit {{id}}.{{type}}.md

# Preview the collated changelog for a version without writing it.
changelog-draft version:
    uv run towncrier build --draft --version {{version}}

# Suggest the next version from the pending news fragments (advisory).
suggest-version:
    uv run python scripts/suggest_version.py

# Validate, collate the changelog, commit, tag, and push a release (see AGENTS.md).
[confirm]
release version: check test
    @test -n "$(find release-notes -type f ! -name README.md)" || { echo "No news fragments in release-notes/ — use a direct tag for migration releases."; exit 1; }
    uv run towncrier build --yes --version {{version}}
    git add CHANGELOG.md release-notes
    git commit -m "release {{version}}"
    git tag -a {{version}} -m "Release {{version}}"
    git push --follow-tags origin HEAD

# Reformat the code using isort and ruff.
[confirm]
reformat:
    uv run ruff format .
    uv run ruff check --select I --fix .

# Serve documentation website for development purposes.
docs:
    uv run --extra docs mkdocs serve

# Build the documentation website.
docs-build:
    uv run --extra docs mkdocs build

# Extract current production requirements. Save to a file by appending `> requirements.txt`.
reqs:
    uv export --no-default-groups

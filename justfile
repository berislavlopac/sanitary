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
    uv run mypy --install-types --non-interactive sanitary/

# Run security checks.
analyze:
    uvx vulture --min-confidence 100 sanitary/
    uvx radon mi --show --multi --min B sanitary/

# Run all checks.
check: lint type analyze

# Extract the latest commits
commits:
    git log $(git describe --tags --abbrev=0)..HEAD --oneline --no-decorate

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

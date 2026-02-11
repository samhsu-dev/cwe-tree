# Development Setup Guide

## Prerequisites

- Python 3.12+
- uv (Universal Python Package Installer)

## Installation

### Option 1: Using uv (Recommended)

Install with dev dependencies:

```bash
# Clone the repository
git clone https://github.com/samhsu-dev/cwe-tree.git
cd cwe-tree

# Sync with dev dependencies
uv sync --dev

# Or just sync base dependencies
uv sync
```

### Option 2: Using pip

```bash
# Install package with dev tools
pip install -e '.[dev]'

# Or install only base package
pip install -e '.'
```

## Development Workflow

### Format Code

```bash
# Using make
make format

# Or manually
uv run isort src/
uv run black src/
```

### Run Quality Checks

```bash
# Using make
make quality

# Or individually
uv run isort --check-only src/
uv run black --check src/
uv run mypy src/
uv run pylint src/
```

### View All Commands

```bash
make help
```

## Dependency Groups

The project uses PEP 735 dependency groups:

- **dev** - All development tools (ipykernel, jupyter, linters, formatters, type checker)

### Available Groups

```bash
# Sync only base dependencies
uv sync

# Sync with dev dependencies
uv sync --dev

# Check what's in each group
uv tree
```

## Jupyter Notebooks

With dev dependencies installed, you can run Jupyter:

```bash
jupyter notebook
# or
jupyter lab
```

The `docs/demo.ipynb` notebook demonstrates all API usage examples.

## Code Quality Standards

All code must pass:

| Tool | Command | Standard |
|------|---------|----------|
| isort | `uv run isort --check-only src/` | Imports sorted |
| black | `uv run black --check src/` | Formatted (100-char line) |
| mypy | `uv run mypy src/` | 0 type errors (strict) |
| pylint | `uv run pylint src/` | 10.00/10 score |

## Configuration

- **pyproject.toml** - Package and tool configuration
- **Makefile** - Development automation
- **Code quality rules** - `.cursor/rules/codequality.mdc`

## Troubleshooting

### `uv sync --dev` not installing dev dependencies?

Ensure you're using the latest version of uv:

```bash
uv --version
# Should be 0.1.0 or later for PEP 735 support

# Update uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Missing dependencies after sync?

Regenerate the lock file:

```bash
rm uv.lock
uv sync --dev
```

### Python version mismatch?

The project requires Python 3.12+:

```bash
python --version
# Should be Python 3.12.0 or higher
```

## Documentation

- **docs/design.md** - Architecture and design
- **docs/traversal.md** - Graph traversal API reference
- **docs/demo.ipynb** - Interactive usage examples
- **README.md** - Quick start guide
- **QUALITY.md** - Code quality standards

## Support

For issues or questions, refer to the project documentation or GitHub issues.


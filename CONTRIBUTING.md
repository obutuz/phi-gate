# Contributing

Issues and pull requests are welcome, especially new healthcare formats and real
false positives.

**Never paste real patient data** into an issue, a test or a commit. Describe the
pattern, and reproduce it with made-up values.

## Set up

```bash
git clone https://github.com/obutuz/phi-gate && cd phi-gate
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

## Before opening a pull request

```bash
python -m unittest discover -s tests     # unit, hook, git, property and stress tests
./demo/run-demo.sh                       # exits 1 if any decision changes
ruff check src tests bench
mypy
shellcheck hooks/run.sh bin/phi-gate demo/run-demo.sh
```

A change that closes a bypass comes with a test that fails without it. Say in the
pull request how you checked that.

phi-gate itself has no runtime dependencies, and that should stay true: it runs
inside a hook on machines where installing packages may not be an option. Test
tooling may use dependencies, and the suite skips what is not installed.

## Adding or widening a detector

A detector that fires on ordinary code gets the whole plugin uninstalled, so a
change needs both sides of the evidence:

1. Tests that show the identifier being caught, and a near miss being left alone.
2. A run of `python3 bench/false_positive_sweep.py` over real code, with the
   numbers in the pull request.

## Versioning

phi-gate follows [semantic versioning](https://semver.org). Configuration keys and
their meaning, exit codes and the audit event format are the public interface. A new detector
can block something that passed before, so detectors may change in a minor
release; the changelog says so.

## Releasing

1. Bump the version in `pyproject.toml`, `src/phi_gate/__init__.py`,
   `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`, and add a
   `## <version> (<date>)` section to `CHANGELOG.md`. Merge that to `main`.
2. Publish a GitHub release whose new tag is `v<version>` on `main`.

Publishing the release runs `.github/workflows/release.yml`: the tests run on
Linux and macOS, the package is built with hash-pinned tools, the
distributions, `SHA256SUMS` and build provenance are attached to the release,
the notes are set from the changelog, and the same files go to PyPI through
Trusted Publishing. `.github/workflows/pypi.yml` can republish an existing
release to PyPI by hand.

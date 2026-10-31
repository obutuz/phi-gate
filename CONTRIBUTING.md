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
```

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

phi-gate follows [semantic versioning](https://semver.org). Configuration keys,
exit codes and the audit event format are the public interface. A new detector
can block something that passed before, so detectors may change in a minor
release; the changelog says so.

# Repository Guidelines

## Project Structure & Module Organization

`greeclimate/` contains the async Python package for discovering, binding, and controlling Gree-compatible HVAC devices. Core modules include `device.py`, `discovery.py`, `network.py`, `cipher.py`, and device metadata helpers. `tests/` contains the pytest suite, with shared fixtures in `tests/conftest.py` and helpers in `tests/common.py`. Root-level scripts such as `gree.py` and `emulator.py` support manual discovery/debugging. `samples/` stores packet captures, while `release/` contains extracted mobile-app assets and should not be treated as primary source code.

## Build, Test, and Development Commands

Use the repository-root `venv/` as the official and only virtual environment. Reuse it when it exists; do not create additional environments such as `.venv/` or `.venv-ifaddr/`. If it is missing, create it before installing dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install flake8 pytest pytest-asyncio pytest-cov
```

Run the test suite:

```bash
pytest --cov-report=xml --cov=greeclimate tests/
```

Run the CI lint checks locally:

```bash
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
```

For release tooling, install Node dependencies with `npm ci`; releases are driven by `npx semantic-release`.

## Coding Style & Naming Conventions

Keep code compatible with the minimum Python version declared in `setup.py` (currently 3.10). Check the CI matrix and `tox.ini` separately; report which interpreters were actually exercised. Do not raise the supported minimum incidentally.

Follow the existing style: 4-space indentation, snake_case functions and variables, PascalCase classes and enums, and explicit async/await for network behavior. Keep public API changes in `greeclimate/__init__.py` intentional. Prefer small, focused modules and avoid broad rewrites of protocol or encryption code without tests.

## Testing Guidelines

Tests use `pytest` with `pytest-asyncio`; `asyncio_mode = auto` is configured in `setup.cfg`. Name test files `test_*.py` and keep issue regressions in `tests/test_issues.py` when they map to reported bugs. Add coverage for state changes, packet parsing, binding behavior, and error handling when changing device or network logic.

## Documentation Guidelines

Do not edit `README.md`, `docs/MIDS.md`, or `docs/HIDS.md` unless the user explicitly requests changes to those files. Code or behavior changes alone are not permission to update them. Keep requested edits concise and narrowly scoped; do not add unsolicited explanations, reference tables, evidence summaries, or architecture/recovery guides.

## Commit & Pull Request Guidelines

History follows conventional commits, for example `feat: add buzzer property`, `fix: handle missing 'val' key`, and `chore(release): 2.1.4 [skip ci]`. Use `feat:`, `fix:`, `chore:`, or another conventional type so semantic-release can classify changes.

Never edit `CHANGELOG.md` directly; semantic-release generates it. Describe behavior changes in the PR description; documentation edits remain subject to the explicit-request rule above.

Pull requests should describe the behavior change, list test commands run, and link related issues. Include device model or packet-capture context when changing discovery, binding, or protocol behavior. Do not commit local virtual environments, caches, coverage output, or generated release artifacts unless the release process explicitly requires them.

## Security & Configuration Tips

Do not publish private network captures, device keys, IP addresses, or credentials. Scrub captures and logs before adding them under `samples/` or attaching them to issues.

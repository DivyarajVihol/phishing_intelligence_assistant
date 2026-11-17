# 07. Coding rules (keeps code short and predictable)

## Size and shape
- Function <= 30 lines. File <= 200 lines (tests excluded). If a file grows past that, stop and ask before splitting.
- One responsibility per function and per file. Views stay thin: validate, call service, render.
- Simple over clever. No metaclasses, decorators-for-fun, deep inheritance, plugin systems, or abstract base classes "for later".
- Prefer plain functions and frozen dataclasses. Add a class only when state is genuinely needed.
- No code for features that are not in the current phase prompt. No speculative options, flags or config.

## Style
- Type hints on every function signature. One-line docstring on public functions.
- Comments only for non-obvious "why". No commented-out code, no leftover `TODO` stubs, no `print` (use `logging`).
- Constants (token lists, thresholds, limits) live in `constants.py` / `rules.py`, never scattered as magic numbers.
- Catch specific exceptions. A broad `except Exception` is allowed only at a connector or orchestrator boundary, where it converts the failure into an `unavailable` finding and logs it.
- Standard library first. No new dependency without asking (see `02_TECH_STACK.md`).

## Working rules for the agent
1. Read `AGENTS.md` and the docs the prompt names before writing anything.
2. Touch **only** the files the prompt lists. Never rewrite or reformat working files. If another file must change, stop and say why.
3. Do not rename contract functions or dataclass fields from `03_ARCHITECTURE.md`. If a contract seems wrong, stop and ask.
4. If the spec is ambiguous, ask a short question instead of guessing.
5. Every module gets tests in the same phase (see below). Run `python manage.py test` and report the result.
6. Finish with: files changed, tests run and result, anything left undone. Then **stop**. Do not start the next phase.

## Tests
- Django `TestCase` (plain `unittest.TestCase` for plain-Python modules). Names: `test_<thing>_<expected>`.
- Network calls are always mocked (`unittest.mock`). Tests never hit PhishTank, URLhaus, DNS or the internet.
- Each module needs: normal case, edge case, and failure case.
- Every UI phase includes the **no-open check** from `05_SECURITY_RULES.md`.
- Known-answer URLs to keep passing (use real TLDs; `.test`/`.example` are not in the public suffix list and parse wrongly):
  - `https://paypal.com.example-login.com/verify` -> registered domain `example-login.com`, subdomain `paypal.com`.
  - `https://trusted-site.com@fake-login.net/` -> hostname `fake-login.net`, userinfo `trusted-site.com`, obfuscation finding raised.

## Git
Small commits, one per phase, message `Phase N: <what>`.

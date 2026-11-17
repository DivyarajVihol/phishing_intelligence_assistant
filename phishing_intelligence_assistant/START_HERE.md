# START HERE: order of use

This pack is for the **Open-Source Phishing Intelligence and Investigation Assistant** (Django). Everything is derived from your project documentation. Copy the whole pack into the root of your new project folder (this file can stay out of the repo).

## Step 1. Set up the project folder (you, ~10 min, no AI)
1. Create the folder `phishing_intelligence_assistant/` and copy this pack's contents into it.
2. `git init`
3. Create the virtual environment and install: `python -m venv .venv`, activate it, then `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` (never commit `.env`).
5. `git add . && git commit -m "Add project spec and agent rules"`

## Step 2. Read and approve the docs (you, ~30 min)
These are *your* decisions. The AI will follow them exactly, so fix anything you disagree with now.

| Order | File | What it locks |
|---|---|---|
| 1 | `docs/01_PROJECT_SPEC.md` | What the app does, MVP, out of scope, wording rules |
| 2 | `docs/02_TECH_STACK.md` | Exact stack, banned additions, settings and env vars |
| 3 | `docs/03_ARCHITECTURE.md` | Folder tree, module contracts, DB tables |
| 4 | `docs/04_ML_DATA_SPEC.md` | Datasets, labels, splits, features, metrics |
| 5 | `docs/05_SECURITY_RULES.md` | SSRF, secrets, safe handling |
| 6 | `docs/06_UI_GUIDELINES.md` | Pages, colours, components |
| 7 | `docs/07_CODING_RULES.md` | Code size limits, style, what not to do |

## Step 3. Agent rules (already written, just verify)
- `AGENTS.md` is always on in Antigravity. It is short on purpose and points to the docs.
- `.agents/rules/*.md` are loaded when relevant (UI, security, ML).
- Open Antigravity on the project folder and check its rules/customization view lists them. If not, see https://antigravity.google/docs/rules (each rule file needs the YAML frontmatter at the top).

## Step 4. Build, one phase at a time
Open `docs/08_BUILD_PLAN.md` and paste the prompts **in order**, one per Antigravity task. After each phase:
1. `python manage.py test` must pass.
2. Read the diff. Reject anything outside the files the prompt allowed.
3. `git commit`.
4. Only then start the next phase.

## Manual tasks that the AI cannot do for you
| Before phase | Task |
|---|---|
| Phase 4 | Download the phishing dataset (PhishTank export, check current terms) and a documented benign dataset into `ml/data/raw/`. Write down source, date and licence. |
| Phase 7 | Get the URLhaus Auth-Key (abuse.ch) and, if available to you, a PhishTank app key. Put them in `.env` only. |
| Phase 12 | Review the brand-domain list the AI proposes. |
| Phase 16 | Run the full manual test set and fill in the test report. |

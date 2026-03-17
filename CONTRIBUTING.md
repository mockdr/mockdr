# Contributing to mockdr

## Development Setup

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m uvicorn main:app --reload --port 8001
```

### Frontend
```bash
cd frontend
npm ci
npm run dev
```

## Code Standards

### Backend (Python)
- **Linting**: `ruff check .` (zero violations)
- **Type checking**: `mypy --strict . --ignore-missing-imports --exclude tests/`
- **Testing**: `pytest --cov --cov-fail-under=85`
- **Style**: PEP 8 via ruff, Google-style docstrings on all public symbols
- **Architecture**: CQRS pattern — commands (mutations) and queries (reads) are separated

### Frontend (TypeScript/Vue)
- **Linting**: `npx eslint src/ --max-warnings=0`
- **Type checking**: `npx vue-tsc --noEmit`
- **Testing**: `npx vitest run --coverage`
- **Style**: Composition API, JSDoc on all exports

## Testing Requirements

See [TESTING.md](TESTING.md) for the full testing standard. Key points:

- Coverage floor: 85% backend, 80% stores, 60% components
- Every new endpoint needs integration tests (success + error cases)
- Every new store action needs a unit test
- Critical path tests must all pass: `pytest -m critical --no-cov`
- Never delete failing tests — fix the code instead

## Pull Request Checklist

- [ ] All CI checks pass
- [ ] No new `skip`/`xfail` without a dated issue link
- [ ] No coverage thresholds lowered
- [ ] Every new public symbol has a docstring
- [ ] ADR written for significant architectural decisions

## Architecture Decision Records

See [docs/adr/](docs/adr/) for existing ADRs. New significant design decisions should be documented as an ADR following the existing format.

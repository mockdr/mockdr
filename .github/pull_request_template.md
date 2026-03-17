## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / endpoint
- [ ] Refactor (no behaviour change)
- [ ] Tests only
- [ ] Documentation / CI

## Testing

<!-- Describe how you verified this works. Include test commands run locally. -->

```
# Backend
pytest --cov --cov-fail-under=85

# Frontend
npm run type-check && npm run test:coverage
```

## Self-review checklist (TESTING.md)

- [ ] No new `skip`, `xfail`, or `fixme` markers without a dated issue link
- [ ] No coverage thresholds were lowered
- [ ] Every new public function / method / class has a docstring
- [ ] Every new domain has a test for the `*_INTERNAL_FIELDS` stripping invariant
- [ ] Every new API endpoint has an integration test (success + at least one error case)
- [ ] Every new store action has a unit test
- [ ] No `as any` or `as unknown as X` introduced in test files
- [ ] No new cross-domain imports in test fixtures
- [ ] Internal fields (`localIp`, `isInfected`, `passphrase`, etc.) are stripped before any API response
- [ ] S1 response envelope preserved (`{"data": [...], "pagination": {...}}`)

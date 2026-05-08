## Summary

- 

## Verification

- [ ] `ruff check src/ tests/`
- [ ] `ruff format --check src/ tests/`
- [ ] `mypy src/ai_siem --ignore-missing-imports`
- [ ] `pytest tests/ -v --cov=ai_siem --cov-report=term-missing`

## Review Prompts

- [ ] External services: Are Redis and Gemini failures visible to operators without breaking expected return types?
- [ ] Degraded/cache behavior: Do alerts or cache stats expose degraded mode, `last_error`, or `last_failure_reason` where relevant?
- [ ] Gemini behavior: Do mock, Gemini, and fallback paths record clear enrichment provenance?
- [ ] Firewall-rule safety: Are generated rules treated as suggestions with source metadata and human-review requirements?
- [ ] Documentation: Are claims about AI, speed, and production readiness supported by code or clearly caveated?

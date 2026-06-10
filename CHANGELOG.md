# Changelog

## [0.2.0] — 2026-06-10

### Added
- `jailbreak` module — 6 test cases (LLM01 / AML.T0054)
- `data_extraction` module — 7 test cases (LLM02, LLM07 / AML.T0024)
- `rag_poisoning` module — 5 test cases (LLM08 / AML.T0020)
- `agent_hijacking` module — 6 test cases (LLM06 / AML.T0053)

### Improved
- OWASP 2025-aligned recommendations — per finding, per module
- Corrected OWASP refs: DE-01, DE-02, DE-07 → LLM07 (System Prompt Leakage)
- Eliminated false positives across all modules via expanded negative_markers
- CLI: --details flag, per-module OWASP/ATLAS display

### Validated
- Full scan: 29 tests, 18 vulnerabilities, 0 false positives
- Target: llama-3.3-70b-versatile via Groq
- Score: 62/100 HIGH

## [0.1.0] — 2026-06-10

### Added
- Initial project structure
- Core engine: BaseModule, Finding, Target, Session, Severity, Status
- Target connector (httpx, OpenAI-compatible APIs)
- Session manager with scoring and risk levels
- `prompt_injection` module — 5 test cases (LLM01 / AML.T0051)
- CLI entry point (click + rich)
- JSON report output
- LEGAL.md, CONTRIBUTING.md, CHANGELOG.md

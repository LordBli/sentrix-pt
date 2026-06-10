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

## [Planned] v3.0 — Adaptive AI Red Teaming

- AI-powered dynamic payload generation per module
- No hardcoded test cases — all vectors generated at runtime
- Context-aware attack adaptation based on target responses
- Continuous learning within a session — failed attacks inform next attempts

## [0.3.0] — 2026-06-10

### Added
- `insecure_output` module — 6 test cases (LLM05 / AML.T0048)
  - XSS payload reproduction
  - SQL injection in generated code
  - Command injection via os.system()
  - Sensitive data exposure via error echo
  - Path traversal in file serving code
  - Insecure deserialization suggestions

### Planned
- SENTRIX-PT Pro — separate adaptive product
  - AI-generated payloads at runtime
  - Context-aware attack adaptation
  - --live mode: real-time attacker/target exchange display

### Validated
- Full scan: 35 tests, 24 vulnerabilities
- Score: 68/100 HIGH
- Target: llama-3.3-70b-versatile via Groq

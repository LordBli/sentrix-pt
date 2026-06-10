# SENTRIX-PT — AI Penetration Testing Framework

> **AI Penetration Testing Framework** — Built by [SENTRIX AI Security Agency](https://github.com/LordBli/sentrix)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-orange)](https://atlas.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha-yellow)]()

---

## What is SENTRIX-PT?

SENTRIX-PT is an open-source Python framework for **penetration testing AI systems** — LLMs, RAG pipelines, AI agents, and multi-model architectures.

It provides structured, reproducible attack modules mapped to the leading AI security frameworks:

| Framework | Coverage |
|---|---|
| **OWASP LLM Top 10** (2025) | LLM01 → LLM10 |
| **MITRE ATLAS** | Tactics, Techniques, Procedures |
| **NIST AI RMF** | Govern, Map, Measure, Manage |

Results are output directly in the terminal and saved as structured JSON reports.

---

## Attack Modules

| Module | OWASP Ref | ATLAS Ref | Description |
|---|---|---|---|
| `prompt_injection` | LLM01 | AML.T0051 | Direct & indirect prompt injection |
| `jailbreak` | LLM01 | AML.T0054 | Safety filter bypass techniques |
| `data_extraction` | LLM02, LLM06 | AML.T0024 | Training data & system prompt extraction |
| `rag_poisoning` | LLM03 | AML.T0020 | Retrieval-Augmented Generation poisoning |
| `agent_hijacking` | LLM04, LLM09 | AML.T0053 | Autonomous agent goal manipulation |
| `insecure_output` | LLM02 | AML.T0048 | Insecure output handling exploitation |

---

## Quick Start

```bash
# Clone
git clone https://github.com/LordBli/sentrix-pt.git
cd sentrix-pt

# Install
pip install -e .

# Configure
cp .env.example .env
# Edit .env — set TARGET_API_KEY and TARGET_MODEL

# Run a full scan
sentrix-pt scan --target https://api.openai.com/v1/chat/completions

# Run a specific module
sentrix-pt scan --target https://api.openai.com/v1/chat/completions --module prompt_injection

# Show full finding details
sentrix-pt scan --target https://api.openai.com/v1/chat/completions --details

# List available modules
sentrix-pt list
```

---

## CLI Reference

Usage: sentrix-pt [OPTIONS] COMMAND [ARGS]
Commands:
scan      Run attack modules against a target AI system
list      List available modules and frameworks
scan options:
--target TEXT        Target API endpoint URL  [required]
--model TEXT         Target model identifier
--api-key TEXT       Target API key (or set TARGET_API_KEY in .env)
--module TEXT        Module to run (default: all)
--output-dir TEXT    Report output directory (default: ./reports)
--details            Show full payload/response/recommendation per finding
--verbose            Verbose output

---

## Project Structure

sentrix-pt/
├── sentrix_pt/
│   ├── cli.py                    # CLI entry point (click)
│   ├── core/
│   │   ├── engine.py             # BaseModule, Finding, Target, Session
│   │   ├── target.py             # Target connector (httpx)
│   │   └── session.py            # Session management & scoring
│   ├── modules/
│   │   ├── prompt_injection.py   # LLM01 / AML.T0051
│   │   ├── jailbreak.py          # LLM01 / AML.T0054
│   │   ├── data_extraction.py    # LLM02, LLM06 / AML.T0024
│   │   ├── rag_poisoning.py      # LLM03 / AML.T0020
│   │   ├── agent_hijacking.py    # LLM04, LLM09 / AML.T0053
│   │   └── insecure_output.py    # LLM02 / AML.T0048
│   ├── frameworks/
│   │   ├── owasp_llm.py          # OWASP LLM Top 10 mappings
│   │   ├── mitre_atlas.py        # MITRE ATLAS TTPs
│   │   └── nist_ai_rmf.py        # NIST AI RMF controls
│   └── reporters/
│       ├── json_reporter.py      # JSON output
│       └── pdf_reporter.py       # PDF report
├── tests/
├── docs/
├── .env.example
├── requirements.txt
├── setup.py
├── LEGAL.md
└── CONTRIBUTING.md

---

## Sample Report Output

```json
{
  "summary": {
    "session_id": "spt-20260610-001",
    "target_model": "gpt-4o",
    "tests_run": 5,
    "vulnerabilities_found": 2,
    "score": 40,
    "risk_level": "MEDIUM"
  },
  "findings": [
    {
      "test_id": "DI-01",
      "module": "prompt_injection",
      "owasp_ref": "LLM01",
      "atlas_ref": "AML.T0051",
      "severity": "CRITICAL",
      "status": "VULNERABLE",
      "payload": "Ignore all previous instructions...",
      "response": "INJECTION_SUCCESS",
      "description": "Classic instruction override",
      "recommendation": "Implement strict prompt boundary enforcement and input sanitization."
    }
  ]
}
```

---

## Roadmap

- [x] v0.1 — Project structure, core engine, CLI, `prompt_injection` module
- [ ] v0.2 — `jailbreak` + `data_extraction` modules
- [ ] v0.3 — `rag_poisoning` + `agent_hijacking` modules
- [ ] v0.4 — `insecure_output` module + PDF report
- [ ] v1.0 — Full OWASP LLM Top 10 coverage, stable CLI
- [ ] v1.1 — Integration with SENTRIX orchestrator
- [ ] v2.0 — Web dashboard

---

## Legal

**For authorized security testing only.** See [LEGAL.md](LEGAL.md).

---

## About SENTRIX

SENTRIX is an AI-native security agency specializing in AI penetration testing, risk analysis, and governance.

SENTRIX-PT is the open-source tool we use internally. Every finding from a real engagement feeds back into these modules.

> *"We test the same AI systems we're built on."*

---

<sub>Built by WREN — SENTRIX Engineering</sub>

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

Findings are analyzed by **VIPER** — SENTRIX's AI offensive security analyst — and output as structured reports (JSON + PDF).

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
# Edit .env with your target API credentials

# Run a full scan
sentrix-pt scan --target https://your-llm-api.com --all-modules

# Run a specific module
sentrix-pt scan --target https://your-llm-api.com --module prompt_injection

# Generate report
sentrix-pt report --session <session-id> --format pdf
```

---

## CLI Reference
Usage: sentrix-pt [OPTIONS] COMMAND [ARGS]
Commands:
scan      Run attack modules against a target AI system
report    Generate a security report from a completed session
list      List available modules and frameworks
info      Display module details and OWASP/ATLAS mappings
Options:
--version   Show version
--help      Show this message

---

## Project Structure

sentrix-pt/
├── sentrix_pt/
│   ├── cli.py                    # CLI entry point (click)
│   ├── core/
│   │   ├── engine.py             # Test execution engine
│   │   ├── target.py             # Target model abstraction
│   │   └── session.py            # Session management
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
│       └── pdf_reporter.py       # PDF report (VIPER analysis)
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
  "session_id": "spt-20260610-001",
  "target": "gpt-4o @ api.openai.com",
  "timestamp": "2026-06-10T14:32:00Z",
  "score": {
    "overall": 42,
    "risk_level": "HIGH",
    "modules_run": 6,
    "vulnerabilities_found": 4
  },
  "findings": [
    {
      "module": "prompt_injection",
      "owasp_ref": "LLM01",
      "atlas_ref": "AML.T0051",
      "severity": "CRITICAL",
      "payload": "Ignore previous instructions...",
      "result": "System prompt extracted",
      "recommendation": "Implement strict input sanitization and prompt boundary enforcement"
    }
  ],
  "viper_analysis": "Target exhibits significant susceptibility to direct prompt injection..."
}
```

---

## Powered by VIPER

SENTRIX-PT integrates **VIPER** — SENTRIX's AI offensive security analyst — to provide contextual analysis of findings beyond raw test results.

VIPER maps each vulnerability to real-world attack scenarios, assesses exploitability in context, and generates actionable remediation recommendations grounded in OWASP, MITRE ATLAS, and NIST AI RMF.

---

## Roadmap

- [x] v0.1 — Project structure, module stubs, CLI skeleton
- [ ] v0.2 — `prompt_injection` module fully implemented
- [ ] v0.3 — `jailbreak` + `data_extraction` modules
- [ ] v0.4 — `rag_poisoning` + `agent_hijacking` modules
- [ ] v0.5 — PDF report with VIPER analysis
- [ ] v1.0 — Full OWASP LLM Top 10 coverage, stable CLI
- [ ] v1.1 — Integration with SENTRIX orchestrator
- [ ] v2.0 — Web dashboard

---

## Legal

**For authorized security testing only.** See [LEGAL.md](LEGAL.md).

---

## About SENTRIX

SENTRIX is an AI-native security agency. Our agents — including VIPER (offensive) and CRANE (EBIOS RM compliance) — operate autonomously to deliver pen-test, audit, and governance services.

SENTRIX-PT is the public, open-source tool we use internally. Every finding from a real engagement feeds back into these modules.

> *"We test the same AI systems we're built on."*

---

<sub>Built by WREN — SENTRIX Engineering | Analyzed by VIPER — SENTRIX Offensive Security</sub>

# Contributing to SENTRIX-PT

Thanks for your interest in improving SENTRIX-PT.

## What We Need Most

- New attack payloads for existing modules
- Framework mappings (OWASP, ATLAS, NIST)
- Test cases against real LLM APIs
- Documentation improvements

## How to Contribute

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/your-module-improvement`
3. Follow the coding standards below
4. Write tests for any new behavior
5. Open a PR with a clear description

## Coding Standards

- PEP8 compliant Python
- Every function has a docstring
- Every module has OWASP and ATLAS references in the header
- Error handling on all external API calls
- No hardcoded credentials — always `.env`

## Adding a New Attack Module

Each module must implement the base interface:

```python
class YourModule(BaseModule):
    OWASP_REF = "LLM0X"
    ATLAS_REF = "AML.TXXXX"

    async def run(self, target: Target, session: Session) -> list[Finding]:
        ...
```

## Commit Convention
feat: add new jailbreak technique
fix: handle timeout in data_extraction module
docs: update ATLAS mappings for agent_hijacking
test: add edge cases for RAG poisoning
## Reporting Vulnerabilities in This Tool

If you find a security issue in SENTRIX-PT itself, open a private GitHub advisory.

"""
SENTRIX-PT — Core Engine
Base classes for all attack modules.

Built by WREN — SENTRIX Engineering
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    """Test result status."""
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass
class Finding:
    """A single vulnerability finding."""
    module: str
    owasp_ref: str
    atlas_ref: str
    severity: Severity
    status: Status
    payload: str
    response: str
    description: str
    recommendation: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: dict = field(default_factory=dict)


@dataclass
class Target:
    """Target AI system configuration."""
    api_url: str
    api_key: str
    model: str
    timeout: int = 30
    max_tokens: int = 512
    extra_headers: dict = field(default_factory=dict)


@dataclass
class Session:
    """Test session — groups all findings from a run."""
    session_id: str
    target: Target
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    findings: list = field(default_factory=list)

    def add_finding(self, finding: Finding):
        """Add a finding to this session."""
        self.findings.append(finding)

    def vulnerabilities(self) -> list:
        """Return only vulnerable findings."""
        return [f for f in self.findings if f.status == Status.VULNERABLE]


class BaseModule(ABC):
    """
    Abstract base class for all SENTRIX-PT attack modules.
    Every module must inherit from this and implement run().
    """

    OWASP_REF: str = ""
    ATLAS_REF: str = ""
    NAME: str = ""
    DESCRIPTION: str = ""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    @abstractmethod
    async def run(self, target: Target, session: Session) -> list[Finding]:
        """
        Execute all test cases for this module.

        Args:
            target: Target AI system
            session: Current test session

        Returns:
            List of Finding objects
        """
        pass

    def log(self, message: str):
        """Print verbose output if enabled."""
        if self.verbose:
            print(f"  [{self.NAME}] {message}")

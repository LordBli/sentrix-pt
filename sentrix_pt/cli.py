"""
SENTRIX-PT — CLI Entry Point
Built by WREN — SENTRIX Engineering
"""

import asyncio
import json
import os

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box

from .core.engine import Target, Severity, Status
from .core.session import create_session, session_summary
from .modules.prompt_injection import PromptInjectionModule
from .modules.jailbreak import JailbreakModule
from .modules.data_extraction import DataExtractionModule
from .modules.rag_poisoning import RAGPoisoningModule

load_dotenv()
console = Console()

MODULES = {
    "prompt_injection": PromptInjectionModule,
    "jailbreak": JailbreakModule,
    "data_extraction": DataExtractionModule,
    "rag_poisoning": RAGPoisoningModule,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_banner():
    console.print("\n[bold red]SENTRIX-PT[/bold red] — AI Penetration Testing Framework")
    console.print("[dim]by SENTRIX AI Security Agency[/dim]\n")


def print_summary(summary: dict):
    risk_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "SECURE": "bold green",
    }
    color = risk_colors.get(summary["risk_level"], "white")
    console.print(f"\n[bold]Session:[/bold] {summary['session_id']}")
    console.print(f"[bold]Target:[/bold]  {summary['target_model']}")
    console.print(f"[bold]Tests:[/bold]   {summary['tests_run']} run — {summary['vulnerabilities_found']} vulnerabilities found")
    console.print(f"[bold]Risk:[/bold]    [{color}]{summary['risk_level']}[/{color}] (score: {summary['score']}/100)\n")


def print_findings(findings: list):
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Module", width=20)
    table.add_column("OWASP", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=16)
    table.add_column("Description")

    for i, f in enumerate(findings):
        if f.status == Status.NOT_VULNERABLE:
            continue
        color = SEVERITY_COLORS.get(f.severity, "white")
        status_color = "red" if f.status == Status.VULNERABLE else "yellow"
        table.add_row(
            str(f.metadata.get("test_id", i)),
            f.module,
            f.owasp_ref,
            f"[{color}]{f.severity.value}[/{color}]",
            f"[{status_color}]{f.status.value}[/{status_color}]",
            f.description,
        )

    console.print(table)


def print_finding_details(findings: list):
    vulns = [f for f in findings if f.status == Status.VULNERABLE]
    if not vulns:
        console.print("[green]No vulnerabilities found.[/green]\n")
        return

    for f in vulns:
        color = SEVERITY_COLORS.get(f.severity, "white")
        console.print(f"[{color}]━━ {f.metadata.get('test_id')} — {f.description} [{f.severity.value}][/{color}]")
        console.print(f"  [bold]Payload:[/bold]        {f.payload}")
        console.print(f"  [bold]Response:[/bold]       {f.response[:300]}")
        console.print(f"  [bold]Recommendation:[/bold] {f.recommendation}\n")


async def run_scan(target: Target, modules: list, verbose: bool, output_dir: str):
    session = create_session(target)
    console.print(f"[dim]Session: {session.session_id}[/dim]")
    console.print(f"[dim]Target:  {target.api_url} ({target.model})[/dim]\n")

    for module_name in modules:
        cls = MODULES.get(module_name)
        if not cls:
            console.print(f"[yellow]Unknown module: {module_name}[/yellow]")
            continue

        console.print(f"[bold]Running module:[/bold] {module_name} ({cls.OWASP_REF} / {cls.ATLAS_REF})")
        module = cls(verbose=verbose)
        await module.run(target, session)
        console.print(f"[green]✓[/green] {module_name} complete\n")

    return session


@click.group()
@click.version_option("0.1.0", prog_name="sentrix-pt")
def main():
    """SENTRIX-PT — AI Penetration Testing Framework."""
    pass


@main.command()
@click.option("--target", required=True, help="Target API endpoint URL")
@click.option("--model", default=None, help="Target model identifier")
@click.option("--api-key", default=None, help="Target API key")
@click.option("--module", default="all", help="Module to run (default: all)")
@click.option("--output-dir", default="./reports", help="Report output directory")
@click.option("--verbose", is_flag=True, help="Verbose output")
@click.option("--details", is_flag=True, help="Show full finding details")
def scan(target, model, api_key, module, output_dir, verbose, details):
    """Run attack modules against a target AI system."""
    print_banner()

    resolved_key = api_key or os.getenv("TARGET_API_KEY", "")
    resolved_model = model or os.getenv("TARGET_MODEL", "gpt-4o")

    if not resolved_key:
        console.print("[red]Error: No API key provided. Use --api-key or set TARGET_API_KEY in .env[/red]")
        return

    t = Target(
        api_url=target,
        api_key=resolved_key,
        model=resolved_model,
    )

    modules = list(MODULES.keys()) if module == "all" else [module]
    session = asyncio.run(run_scan(t, modules, verbose, output_dir))
    summary = session_summary(session)

    print_summary(summary)
    print_findings(session.findings)

    if details:
        print_finding_details(session.findings)

    os.makedirs(output_dir, exist_ok=True)
    report_path = f"{output_dir}/{session.session_id}.json"
    with open(report_path, "w") as f:
        json.dump({
            "summary": summary,
            "findings": [
                {
                    "test_id": fi.metadata.get("test_id"),
                    "module": fi.module,
                    "owasp_ref": fi.owasp_ref,
                    "atlas_ref": fi.atlas_ref,
                    "severity": fi.severity.value,
                    "status": fi.status.value,
                    "payload": fi.payload,
                    "response": fi.response,
                    "description": fi.description,
                    "recommendation": fi.recommendation,
                    "timestamp": fi.timestamp,
                }
                for fi in session.findings
            ]
        }, f, indent=2)

    console.print(f"[dim]Report saved: {report_path}[/dim]\n")


@main.command("list")
def list_modules():
    """List available attack modules."""
    print_banner()
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    table.add_column("Module")
    table.add_column("OWASP")
    table.add_column("ATLAS")
    table.add_column("Description")
    for name, cls in MODULES.items():
        table.add_row(name, cls.OWASP_REF, cls.ATLAS_REF, cls.DESCRIPTION)
    console.print(table)


if __name__ == "__main__":
    main()

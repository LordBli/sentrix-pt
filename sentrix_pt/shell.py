"""
SENTRIX-PT — Interactive Shell
Metasploit-style interactive interface with autocomplete and history.

Built by WREN — SENTRIX Engineering
"""

import asyncio
import json
import os

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

from .core.engine import Target, Severity, Status
from .core.session import create_session, session_summary
from .modules.prompt_injection import PromptInjectionModule
from .modules.jailbreak import JailbreakModule
from .modules.data_extraction import DataExtractionModule
from .modules.rag_poisoning import RAGPoisoningModule
from .modules.agent_hijacking import AgentHijackingModule
from .modules.insecure_output import InsecureOutputModule

load_dotenv()
console = Console()

MODULES = {
    "prompt_injection": PromptInjectionModule,
    "jailbreak": JailbreakModule,
    "data_extraction": DataExtractionModule,
    "rag_poisoning": RAGPoisoningModule,
    "agent_hijacking": AgentHijackingModule,
    "insecure_output": InsecureOutputModule,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

BANNER = """[bold red]
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗██╗  ██╗    ██████╗ ████████╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║╚██╗██╔╝    ██╔══██╗╚══██╔══╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║ ╚███╔╝     ██████╔╝   ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║ ██╔██╗     ██╔═══╝    ██║
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║██║██╔╝ ██╗    ██║        ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝        ╚═╝
[/bold red]"""

CORE_COMMANDS = ["use", "modules", "help", "exit", "quit", "?"]
MODULE_COMMANDS = ["run", "set", "options", "info", "back", "help", "exit", "quit", "?"]
MODULE_OPTIONS = ["target", "model", "api-key", "output-dir", "verbose", "details"]

PROMPT_STYLE = Style.from_dict({
    "prompt.module": "#ff0000 bold",
    "prompt.bracket": "#ffffff",
    "prompt.arrow": "#ffffff bold",
})


# ---------------------------------------------------------------------------
# Autocompleter
# ---------------------------------------------------------------------------

class SentrixCompleter(Completer):
    """Dynamic autocompleter — adapts to current shell context."""

    def __init__(self, state: dict):
        self.state = state

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        words = text.split()
        word = document.get_word_before_cursor()

        current_module = self.state.get("module")

        # Empty input — suggest all commands
        if not words or (len(words) == 1 and not text.endswith(" ")):
            commands = MODULE_COMMANDS if current_module else CORE_COMMANDS
            for cmd in commands:
                if cmd.startswith(word):
                    yield Completion(cmd, start_position=-len(word))
            return

        cmd = words[0].lower()

        # use <module> — autocomplete module names
        if cmd == "use" and not current_module:
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                for name in ["all"] + list(MODULES.keys()):
                    if name.startswith(word):
                        yield Completion(name, start_position=-len(word))

        # set <option> — autocomplete option names
        elif cmd == "set" and current_module:
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                for opt in MODULE_OPTIONS:
                    if opt.startswith(word):
                        yield Completion(opt, start_position=-len(word))

            # set verbose/details — autocomplete true/false
            elif len(words) >= 2 and words[1] in ("verbose", "details"):
                if len(words) == 2 or (len(words) == 3 and not text.endswith(" ")):
                    for val in ["true", "false"]:
                        if val.startswith(word):
                            yield Completion(val, start_position=-len(word))


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_banner():
    console.print(BANNER)
    console.print("  [white]    SENTRIX-PT v0.3.0 — AI Penetration Testing Framework[/white]")
    console.print(f"  [dim]    {len(MODULES)} modules loaded | 35 test cases | OWASP LLM Top 10 2025[/dim]")
    console.print("  [dim]    SENTRIX AI Security Agency | Type 'help' or '?' for commands[/dim]\n")


def print_core_help():
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
    table.add_column("Command", style="bold white", width=12)
    table.add_column("Description")
    rows = [
        ("use <module>",      "Select a module"),
        ("use all",           "Select all modules"),
        ("modules",           "List all available modules"),
        ("modules --verbose", "List modules with test case details"),
        ("help / ?",          "Show available commands"),
        ("exit",              "Exit SENTRIX-PT"),
    ]
    for cmd, desc in rows:
        table.add_row(cmd, desc)
    console.print("\n[bold]Core Commands[/bold]")
    console.print(table)
    console.print("[dim]  Tip: TAB for autocomplete | ↑↓ for command history[/dim]\n")


def print_module_help(module_name: str, options: dict):
    cmd_table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
    cmd_table.add_column("Command", style="bold white", width=16)
    cmd_table.add_column("Description")
    rows = [
        ("run",             "Execute the module against the target"),
        ("set <opt> <val>", "Set a module option"),
        ("options",         "Show current module options"),
        ("info",            "Show module details"),
        ("back",            "Return to main prompt"),
        ("help / ?",        "Show available commands"),
        ("exit",            "Exit SENTRIX-PT"),
    ]
    for cmd, desc in rows:
        cmd_table.add_row(cmd, desc)
    console.print("\n[bold]Module Commands[/bold]")
    console.print(cmd_table)

    opt_table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
    opt_table.add_column("Option", style="bold white", width=14)
    opt_table.add_column("Value", width=42)
    opt_table.add_column("Required", width=10)

    required = {"target": "YES", "api-key": "YES"}
    defaults = {"model": "gpt-4o", "output-dir": "./reports", "verbose": "false", "details": "false"}

    for opt in MODULE_OPTIONS:
        value = options.get(opt, defaults.get(opt, "(not set)"))
        if opt == "api-key" and value and value != "(not set)":
            value = value[:8] + "***" + value[-4:]
        req = required.get(opt, "NO")
        color = "green" if value != "(not set)" else "dim"
        opt_table.add_row(opt, f"[{color}]{value}[/{color}]", req)

    console.print("\n[bold]Module Options[/bold]")
    console.print(opt_table)
    console.print("[dim]  Tip: TAB for autocomplete | ↑↓ for command history[/dim]\n")


def print_modules():
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold red")
    table.add_column("Name", style="bold white", width=22)
    table.add_column("OWASP", width=8)
    table.add_column("ATLAS", width=12)
    table.add_column("Description")
    for name, cls in MODULES.items():
        table.add_row(name, cls.OWASP_REF, cls.ATLAS_REF, cls.DESCRIPTION)
    console.print("\n[bold]Available Modules[/bold]")
    console.print(table)


def print_module_info(module_name: str):
    cls = MODULES.get(module_name)
    if not cls:
        return
    console.print(f"\n[bold]Module:[/bold]      [red]{module_name}[/red]")
    console.print(f"[bold]OWASP Ref:[/bold]   {cls.OWASP_REF}")
    console.print(f"[bold]ATLAS Ref:[/bold]   {cls.ATLAS_REF}")
    console.print(f"[bold]Description:[/bold] {cls.DESCRIPTION}")
    console.print(f"[bold]Docstring:[/bold]   {cls.__doc__.strip().splitlines()[0]}\n")


def print_findings_table(findings: list):
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
        console.print("[green][*] No vulnerabilities found.[/green]\n")
        return
    for f in vulns:
        color = SEVERITY_COLORS.get(f.severity, "white")
        console.print(f"[{color}]━━ {f.metadata.get('test_id')} — {f.description} [{f.severity.value}][/{color}]")
        console.print(f"  [bold]Payload:[/bold]        {f.payload}")
        console.print(f"  [bold]Response:[/bold]       {f.response[:300]}")
        console.print(f"  [bold]Recommendation:[/bold] {f.recommendation}\n")


# ---------------------------------------------------------------------------
# Module execution
# ---------------------------------------------------------------------------

async def execute_module(module_name: str, options: dict):
    cls = MODULES.get(module_name)
    resolved_key = options.get("api-key") or os.getenv("TARGET_API_KEY", "")
    resolved_model = options.get("model") or os.getenv("TARGET_MODEL", "gpt-4o")
    resolved_target = options.get("target", "")
    output_dir = options.get("output-dir", "./reports")
    verbose = options.get("verbose", "false").lower() == "true"
    details = options.get("details", "false").lower() == "true"

    if not resolved_target:
        console.print("[red][-] Target not set. Use: set target <url>[/red]")
        return
    if not resolved_key:
        console.print("[red][-] API key not set. Use: set api-key <key>[/red]")
        return

    t = Target(api_url=resolved_target, api_key=resolved_key, model=resolved_model)
    session = create_session(t)

    console.print(f"\n[*] Session: [dim]{session.session_id}[/dim]")
    console.print(f"[*] Target:  [dim]{resolved_target} ({resolved_model})[/dim]")
    console.print(f"[*] Module:  [bold]{module_name}[/bold] ({cls.OWASP_REF} / {cls.ATLAS_REF})\n")

    module = cls(verbose=verbose)
    await module.run(t, session)

    summary = session_summary(session)
    risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "SECURE": "bold green"}
    color = risk_colors.get(summary["risk_level"], "white")

    console.print(f"\n[bold]Session:[/bold] {summary['session_id']}")
    console.print(f"[bold]Tests:[/bold]   {summary['tests_run']} run — {summary['vulnerabilities_found']} vulnerabilities found")
    console.print(f"[bold]Risk:[/bold]    [{color}]{summary['risk_level']}[/{color}] (score: {summary['score']}/100)\n")

    print_findings_table(session.findings)

    if details:
        print_finding_details(session.findings)

    os.makedirs(output_dir, exist_ok=True)
    report_path = f"{output_dir}/{session.session_id}.json"
    with open(report_path, "w") as fh:
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
        }, fh, indent=2)
    console.print(f"[dim][*] Report saved: {report_path}[/dim]\n")


# ---------------------------------------------------------------------------
# Main shell loop
# ---------------------------------------------------------------------------

def run_shell():
    """Launch interactive shell with autocomplete and history."""
    print_banner()
    print_core_help()

    state = {"module": None}
    options = {}
    history = InMemoryHistory()

    session = PromptSession(
        history=history,
        completer=SentrixCompleter(state),
        complete_while_typing=True,
        style=PROMPT_STYLE,
    )

    while True:
        try:
            if state["module"]:
                prompt = HTML(f'<prompt.module>sentrix-pt</prompt.module><prompt.bracket> (</prompt.bracket><prompt.module>{state["module"]}</prompt.module><prompt.bracket>)</prompt.bracket><prompt.arrow> > </prompt.arrow>')
            else:
                prompt = HTML('<prompt.module>sentrix-pt</prompt.module><prompt.arrow> > </prompt.arrow>')

            raw = session.prompt(prompt).strip()

            if not raw:
                continue

            parts = raw.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("exit", "quit"):
                console.print("\n[dim][*] SENTRIX-PT terminated.[/dim]\n")
                break

            elif cmd in ("help", "?"):
                if state["module"]:
                    print_module_help(state["module"], options)
                else:
                    print_core_help()

            elif cmd == "modules":
                if args and args[0] == "--verbose":
                    print_modules_verbose()
                else:
                    print_modules()

            elif cmd == "use":
                if not args:
                    console.print("[red][-] Usage: use <module_name>[/red]")
                elif args[0] != "all" and args[0] not in MODULES:
                    console.print(f"[red][-] Unknown module: {args[0]}[/red]")
                    console.print(f"[dim][*] Available: all, {', '.join(MODULES.keys())}[/dim]")
                else:
                    if args[0] == "all":
                        state["module"] = "all"
                        options = {}
                        console.print(f"[green][+] Module set: [bold]all[/bold] ({len(MODULES)} modules)[/green]")
                        console.print(f"[dim][*] All modules will run sequentially — 35 test cases[/dim]")
                        console.print("[dim][*] Type 'options' to see settings, 'run' to execute.[/dim]")
                    else:
                        state["module"] = args[0]
                        options = {}
                        console.print(f"[green][+] Module set: [bold]{state['module']}[/bold][/green]")
                        console.print(f"[dim][*] {MODULES[state['module']].OWASP_REF} / {MODULES[state['module']].ATLAS_REF} — {MODULES[state['module']].DESCRIPTION}[/dim]")
                        console.print("[dim][*] Type 'options' to see settings, 'run' to execute.[/dim]")

            elif cmd == "back":
                if state["module"]:
                    state["module"] = None
                    options = {}
                    console.print("[dim][*] Returned to main prompt.[/dim]")

            elif cmd == "info":
                if state["module"]:
                    print_module_info(state["module"])
                else:
                    console.print("[red][-] No module selected. Use: use <module_name>[/red]")

            elif cmd == "options":
                if state["module"]:
                    print_module_help(state["module"], options)
                else:
                    console.print("[red][-] No module selected. Use: use <module_name>[/red]")

            elif cmd == "set":
                if not state["module"]:
                    console.print("[red][-] No module selected. Use: use <module_name>[/red]")
                elif len(args) < 2:
                    console.print("[red][-] Usage: set <option> <value>[/red]")
                elif args[0] not in MODULE_OPTIONS:
                    console.print(f"[red][-] Unknown option: {args[0]}[/red]")
                    console.print(f"[dim][*] Available: {', '.join(MODULE_OPTIONS)}[/dim]")
                else:
                    options[args[0]] = " ".join(args[1:])
                    console.print(f"[green][+] {args[0]} => {options[args[0]]}[/green]")

            elif cmd == "run":
                if not state["module"]:
                    console.print("[red][-] No module selected. Use: use <module_name>[/red]")
                elif state["module"] == "all":
                    for mod_name in MODULES.keys():
                        asyncio.run(execute_module(mod_name, options))
                else:
                    asyncio.run(execute_module(state["module"], options))

            else:
                console.print(f"[red][-] Unknown command: {cmd}[/red]")
                console.print("[dim][*] Type 'help' or '?' for available commands.[/dim]")

        except KeyboardInterrupt:
            console.print("\n[dim][*] Use 'exit' to quit.[/dim]")
        except EOFError:
            console.print("\n[dim][*] SENTRIX-PT terminated.[/dim]\n")
            break


def print_modules_verbose():
    """Print all modules with test case details."""
    from .modules.prompt_injection import DIRECT_INJECTION_TESTS
    from .modules.jailbreak import JAILBREAK_TESTS
    from .modules.data_extraction import DATA_EXTRACTION_TESTS
    from .modules.rag_poisoning import RAG_POISONING_TESTS
    from .modules.agent_hijacking import AGENT_HIJACKING_TESTS
    from .modules.insecure_output import INSECURE_OUTPUT_TESTS

    TEST_CASES = {
        "prompt_injection": DIRECT_INJECTION_TESTS,
        "jailbreak": JAILBREAK_TESTS,
        "data_extraction": DATA_EXTRACTION_TESTS,
        "rag_poisoning": RAG_POISONING_TESTS,
        "agent_hijacking": AGENT_HIJACKING_TESTS,
        "insecure_output": INSECURE_OUTPUT_TESTS,
    }

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold red")
    table.add_column("Module", style="bold white", width=22)
    table.add_column("OWASP", width=8)
    table.add_column("ATLAS", width=12)
    table.add_column("Tests", width=6)
    table.add_column("Description")
    for name, cls in MODULES.items():
        tests = TEST_CASES.get(name, [])
        table.add_row(name, cls.OWASP_REF, cls.ATLAS_REF, str(len(tests)), cls.DESCRIPTION)
    console.print("\n[bold]Available Modules[/bold]")
    console.print(table)

    for name, cls in MODULES.items():
        tests = TEST_CASES.get(name, [])
        console.print(f"\n[bold red]{name}[/bold red] — {cls.OWASP_REF} / {cls.ATLAS_REF}")
        for t in tests:
            sev = t['severity'].value
            color = "bold red" if sev == "CRITICAL" else "red" if sev == "HIGH" else "yellow"
            console.print(f"  [dim]{t['id']}[/dim]  {t['description']}  [[{color}]{sev}[/{color}]]")

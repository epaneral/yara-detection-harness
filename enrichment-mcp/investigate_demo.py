"""
Demo: YARA flagging -> chained VirusTotal investigation, end to end.

Compiles the repo's YARA rules, scans the corpus, and for each *flagged* sample
hands its text to the enrichment server's investigate_sample tool over stdio --
the literal "auto-extract indicators from a flagged sample and chain the lookup"
flow. YARA stays out of the server: only this demo imports it.

Needs yara-python (a demo-only dependency, NOT in requirements.txt) alongside the
server's deps. With the server venv active:
    pip install yara-python
Run (a key in .env gives live verdicts; without one the chain still runs and
each indicator reports the actionable key-not-set message):
    python investigate_demo.py
"""

import asyncio
import pathlib
import sys

import yara
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
SERVER = str(HERE / "server.py")
RULES_DIR = REPO / "rules"
CORPUS_DIR = REPO / "corpus"


def _flagged_samples():
    """Compile the rules and return [(path, [rule names])] for samples that match."""
    rules = yara.compile(filepaths={p.stem: str(p) for p in sorted(RULES_DIR.glob("*.yar"))})
    flagged = []
    for sample in sorted(CORPUS_DIR.rglob("*")):
        if sample.is_file() and (matches := rules.match(data=sample.read_bytes())):
            flagged.append((sample, [m.rule for m in matches]))
    return flagged


async def main():
    flagged = _flagged_samples()
    if not flagged:
        print("No flagged samples found.")
        return
    print(f"{len(flagged)} flagged sample(s); investigating each over stdio...\n")

    # Launch the server under this interpreter so it shares the deps and finds .env.
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for sample, rule_names in flagged:
                rel = sample.relative_to(REPO).as_posix()
                print(f"=== {rel}  (flagged by: {', '.join(rule_names)}) ===")
                result = await session.call_tool(
                    "investigate_sample", {"params": {"text": sample.read_text()}}
                )
                for block in result.content:
                    print(getattr(block, "text", block))
                print()


if __name__ == "__main__":
    asyncio.run(main())

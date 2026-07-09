"""Two-path IOC ingestion: collect indicators from a structured feed and (PR2) a
scraped static source, normalize them, and dedup into a JSONL store. CLI-driven,
deliberately independent of the enrichment MCP server. See docs/tier5-ingestion.md."""

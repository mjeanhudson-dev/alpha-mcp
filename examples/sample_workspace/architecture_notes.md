# Stage 0 Local MCP Vault Architecture Notes

This sample document demonstrates Markdown ingestion, 160-line slicing, and automatic URL harvesting across categories.

## Core Design Principles

1. **Zero-Dependency Local Execution**: Runs strictly on the Python 3.10+ standard library (`sqlite3`, `ast`, `mmap`, `zipfile`, `concurrent.futures`).
2. **SHA-256 Deduplication**: Identical backup copies (such as `backup/demo_mcp_server_copy.py`) are hashed via `mmap` and shunted automatically so duplicate slices never bloat the FTS5 index.
3. **Pre-Index Secret Sieve**: Credentials matching API key, OAuth, private key, or `.env` patterns are scrubbed to `[REDACTED:<TYPE>]` before slices enter `slices_fts`.
4. **Safe Archive Inspection**: Virtual hard disks (`.vhdx`) are inspected read-only via `7z l -slt` and `.zip` archives are cataloged via `zipfile.ZipFile.infolist()` with zero extraction.

## Public Reference Links

- Model Context Protocol Specification: https://modelcontextprotocol.io/specification/2025-03-26
- MCP Specification Repository: https://github.com/modelcontextprotocol/specification
- Hugging Face Documentation Hub: https://huggingface.co/docs
- SQLite FTS5 Full-Text Search Reference: https://www.sqlite.org/fts5.html
- Python Standard Library `sqlite3` Docs: https://docs.python.org/3/library/sqlite3.html

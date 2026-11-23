FROM python:3.12-slim

ENV PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ALPHA_MCP_VAULT_DB=/app/mcp_alpha_vault.sqlite3

WORKDIR /app

RUN groupadd --gid 10001 alpha \
    && useradd --uid 10001 --gid 10001 --home-dir /app --no-create-home --shell /usr/sbin/nologin alpha \
    && chown 10001:10001 /app

COPY --chown=10001:10001 alpha_mcp_server.py mcp_carbon_ingest.py ./
COPY --chown=10001:10001 examples/sample_workspace ./examples/sample_workspace

USER 10001:10001

RUN python mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db /app/mcp_alpha_vault.sqlite3 --vhdx-mode inspect

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).read()"]

ENTRYPOINT ["python", "alpha_mcp_server.py", "--transport", "http", "--host", "0.0.0.0", "--port", "8080", "--require-auth"]

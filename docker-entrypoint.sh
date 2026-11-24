#!/bin/sh
# Start the Drost MCP server as an HTTP service when configured to; otherwise keep the
# container alive as a stdio execution environment for `docker exec -i ... drost-mcp`.
set -eu

case "${DROST_MCP_TRANSPORT:-}" in
    streamable-http|http)
        exec drost-mcp --transport streamable-http
        ;;
    ""|stdio)
        if [ -n "${DROST_MCP_AUTH_TOKEN:-}" ] && [ -z "${DROST_MCP_TRANSPORT:-}" ]; then
            exec drost-mcp --transport streamable-http
        fi
        exec "$@"
        ;;
    *)
        echo "docker-entrypoint: unsupported DROST_MCP_TRANSPORT=${DROST_MCP_TRANSPORT}" >&2
        exit 64
        ;;
esac

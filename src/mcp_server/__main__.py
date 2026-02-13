"""
MCP Server main entry point.

Run with: python -m src.mcp_server

This starts the FastMCP server with stdio transport for communication with
the OpenAI Agents SDK MCP client.
"""

from .server import mcp

if __name__ == "__main__":
    # Run with stdio transport (required for MCPServerStdio client)
    mcp.run(transport="stdio")

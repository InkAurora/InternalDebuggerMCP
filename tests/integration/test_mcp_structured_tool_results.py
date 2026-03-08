from __future__ import annotations

import sys
import unittest
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))


class McpStructuredToolResultsTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_injection_setup_returns_structured_content_without_text_mirror(self) -> None:
        server = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SRC / "launch.py")],
            cwd=str(MCP_SRC),
            env={"PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"},
        )

        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("get_injection_setup")

        self.assertFalse(result.isError)
        self.assertEqual(result.content, [])
        self.assertIsNotNone(result.structuredContent)
        assert result.structuredContent is not None
        self.assertIn("layout_mode", result.structuredContent)
        self.assertIn("injector_path", result.structuredContent)


if __name__ == "__main__":
    unittest.main()
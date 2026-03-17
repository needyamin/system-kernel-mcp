# SystemKernelMCP

Cross-platform MCP server for terminal, OS info, and process listing. Works on Windows, Linux, macOS.

## Tools

| Tool | Description |
|------|-------------|
| `execute_terminal_command` | Run shell commands (timeout: 120s) |
| `run_commands` | Run multiple commands in sequence |
| `get_os_info` | OS, kernel, arch, Python, CWD |
| `get_running_processes` | Top processes by CPU |
| `get_current_user` | Username and UID |
| `read_file` | Read file contents |
| `list_directory` | List files/folders |
| `write_file` | Write or append to file |
| `file_exists` | Check if path exists |
| `ping_host` | Ping a host |
| `check_port` | Check if TCP port is open |
| `get_network_info` | IP addresses, interfaces |
| `get_environment_vars` | List env vars (optional prefix) |
| `check_tool_installed` | Check if CLI tool exists |
| `get_services` | Running services |

## Install

```bash
python -m venv venv
# Windows: .\venv\Scripts\Activate
# Unix: source venv/bin/activate
pip install mcp
```

## Run

```bash
python system_mcp.py
```

## Cursor / Claude Desktop

Add to MCP config:

```json
{
  "mcpServers": {
    "SystemKernelMCP": {
      "command": "python",
      "args": ["system_mcp.py"],
      "cwd": "C:\\path\\to\\MCP SERVER"
    }
  }
}
```

## Docs

Open [index.html](index.html) in a browser.

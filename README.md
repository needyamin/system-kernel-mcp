# SystemKernelMCP

**130+ tools** for full system control: terminal, Git, Docker, Kubernetes, VMs, BIOS, kernel, pentesting, AI, cloud. Works with **Cursor, Claude Desktop, Windsurf**, and any MCP client.

[![GitHub](https://img.shields.io/badge/GitHub-needyamin%2Fsystem--kernel--mcp-blue)](https://github.com/needyamin/system-kernel-mcp)

---

## What is this?

SystemKernelMCP is an **MCP (Model Context Protocol) server**. It gives your AI assistant (Cursor, Claude, etc.) 130+ tools to control your system: run terminal commands, manage Docker, check ports, read files, and more.

**You do NOT run it yourself.** Your AI client (Cursor, Claude) starts it automatically when you ask for a tool.

---

## Quick Start (3 steps)

### Step 1: Install

```bash
# Create virtual environment
python -m venv venv

# Activate (pick one for your terminal)
# Windows CMD:        .\venv\Scripts\activate
# Windows Git Bash:   source venv/Scripts/activate
# Mac/Linux:          source venv/bin/activate

# Install MCP
pip install mcp
```

### Step 2: Add to your AI client

**For Cursor:** This project already has `.cursor/mcp.json`. Just open the folder in Cursor.

**For Claude Desktop:** Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "SystemKernelMCP": {
      "command": "python",
      "args": ["C:\\full\\path\\to\\MCP SERVER\\system_mcp.py"],
      "cwd": "C:\\full\\path\\to\\MCP SERVER"
    }
  }
}
```

**For other clients:** Add the same config to your client's MCP settings.

### Step 3: Restart and use

1. Restart Cursor (or your AI client)
2. Enable **SystemKernelMCP** in Settings → MCP
3. In chat, ask: *"Run get_os_info"* or *"Ping google.com"*
4. Approve the tool when prompted

**Health check:** If `get_os_info` returns your OS info, it's working.

---

## Important: Do NOT run manually

```bash
python system_mcp.py   # ❌ Wrong - will show a message and exit
```

This is a **stdio server**. It talks over stdin/stdout. Your AI client starts it automatically. Running it in a terminal does nothing useful.

---

## Supported clients

| Client | Config location |
|--------|-----------------|
| **Cursor** | `.cursor/mcp.json` (in project) |
| **Claude Desktop** | `claude_desktop_config.json` |
| **Windsurf** | Similar to Cursor |
| **Custom** | Any MCP client that supports stdio |

---

## Tools (130+)

| Category | Examples |
|----------|----------|
| **Terminal** | `execute_terminal_command`, `run_commands` |
| **OS** | `get_os_info`, `get_running_processes`, `get_services` |
| **Files** | `read_file`, `write_file`, `list_directory`, `file_hash`, `grep_files` |
| **Network** | `ping_host`, `check_port`, `dns_lookup`, `http_request`, `ssl_cert_info` |
| **Docker** | `docker_ps`, `docker_logs`, `docker_exec`, `docker_compose_up` |
| **Kubernetes** | `k8s_pods`, `k8s_logs`, `k8s_apply`, `k8s_delete` |
| **Git** | `git_status`, `git_clone`, `git_push`, `git_commit` |
| **GitHub** | `gh_repos`, `gh_pr_list`, `gh_issue_list` |
| **VMs** | `hyperv_list_vms`, `virtualbox_list_vms`, `wsl_run`, `qemu_list_vms` |
| **BIOS/Kernel** | `bios_info`, `kernel_sysctl_get`, `kernel_modules_list` |
| **Pentesting** | `nmap_scan`, `port_scan_range`, `hash_crack_check`, `subdomain_enum` |
| **AI** | `openai_chat`, `ollama_chat` |
| **Cloud** | `terraform_plan`, `aws_cli`, `gcloud_cli` |
| **Dev** | `python_run`, `venv_create`, `pip_install` |

Full list: [index.html](index.html)

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "No such file" in Cursor | Use absolute path in `args` and `cwd` |
| MCP not in tools list | Restart Cursor, enable in Settings → MCP |
| "Invalid JSON" when running manually | Normal. Don't run manually. Use from Cursor. |
| venv activate fails in Git Bash | Use `source venv/Scripts/activate` |

---

## Requirements

- **Python 3.10+**
- **Optional** (for specific tools): docker, kubectl, gh, git, nmap, terraform, aws, gcloud, redis-cli, whois, VirtualBox, VMware, Hyper-V, WSL

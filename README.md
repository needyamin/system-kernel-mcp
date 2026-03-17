# SystemKernelMCP

**130+ tools** for full system control: terminal, Git, GitHub, Docker, Kubernetes, VMs, BIOS, kernel, DevOps, pentesting, AI, cloud, infra. Cross-platform (Windows, Linux, macOS).

[![GitHub](https://img.shields.io/badge/GitHub-needyamin%2Fsystem--kernel--mcp-blue)](https://github.com/needyamin/system-kernel-mcp)

## Features

- **Terminal & OS** – Run commands, processes, services, env vars
- **Files** – Read, write, list, hash, grep, diff
- **Network** – Ping, port scan, DNS, HTTP, SSL cert, ARP, routing
- **Pentesting** – Port checks, JWT decode, base64, file hash
- **Docker** – Containers, images, logs, exec, compose
- **Kubernetes** – Pods, services, deployments, apply, delete
- **VMs** – Hyper-V, VirtualBox, VMware, WSL, QEMU/KVM
- **BIOS/UEFI** – BIOS info, UEFI variables
- **Kernel** – Sysctl, modules, boot params
- **Git/GitHub** – Clone, push, commit, PRs, issues
- **Docker Hub** – Login, push, tag
- **DevOps** – SSH, SCP, rsync, curl
- **Pentesting** – Nmap, hash crack, subdomain enum
- **AI/LLM** – OpenAI, Ollama (local)
- **Cloud** – AWS, GCP CLI, Terraform
- **Data** – SQLite, GraphQL, Redis
- **Dev** – Python run, venv, pip

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

## MCP Config (Cursor / Claude)

**Project config** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "SystemKernelMCP": {
      "command": "python",
      "args": ["${workspaceFolder}/system_mcp.py"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

**Absolute path** (if workspaceFolder fails):

```json
{
  "mcpServers": {
    "SystemKernelMCP": {
      "command": "python",
      "args": ["C:\\path\\to\\MCP SERVER\\system_mcp.py"],
      "cwd": "C:\\path\\to\\MCP SERVER"
    }
  }
}
```

## Tools (100+)

| Category | Tools |
|----------|-------|
| **Terminal** | `execute_terminal_command`, `run_commands` |
| **OS** | `get_os_info`, `get_running_processes`, `get_current_user`, `get_services`, `get_system_uptime`, `get_scheduled_tasks` |
| **Files** | `read_file`, `write_file`, `list_directory`, `file_exists`, `file_hash`, `grep_files`, `diff_files` |
| **Network** | `ping_host`, `check_port`, `get_network_info`, `dns_lookup`, `http_request`, `ssl_cert_info`, `list_listening_ports`, `get_arp_table`, `get_routing_table` |
| **Utils** | `get_environment_vars`, `check_tool_installed`, `base64_encode`, `base64_decode`, `decode_jwt`, `timestamp_convert`, `generate_uuid`, `get_disk_usage` |
| **Git** | `git_status`, `git_clone`, `git_pull`, `git_push`, `git_commit`, `git_log`, `git_branch`, `git_diff` |
| **GitHub** | `gh_repos`, `gh_repo_create`, `gh_pr_list`, `gh_issue_list` |
| **Docker** | `docker_ps`, `docker_images`, `docker_logs`, `docker_exec`, `docker_inspect`, `docker_stats`, `docker_run`, `docker_compose_up`, `docker_compose_down` |
| **Docker Hub** | `docker_login`, `docker_push`, `docker_tag` |
| **Kubernetes** | `k8s_pods`, `k8s_services`, `k8s_deployments`, `k8s_nodes`, `k8s_logs`, `k8s_describe`, `k8s_exec`, `k8s_apply`, `k8s_delete`, `k8s_context` |
| **DevOps** | `ssh_run`, `scp_copy`, `rsync_copy`, `curl_request` |
| **Encoding** | `url_encode`, `url_decode`, `hex_encode`, `hex_decode`, `json_format`, `regex_test` |
| **Pentesting** | `nmap_scan`, `port_scan_range`, `hash_generate`, `hash_crack_check`, `subdomain_enum` |
| **AI/LLM** | `openai_chat`, `ollama_chat` |
| **Data** | `sqlite_query`, `graphql_query`, `whois_lookup`, `redis_cli` |
| **Cloud/Infra** | `terraform_plan`, `terraform_apply`, `aws_cli`, `gcloud_cli` |
| **Dev** | `python_run`, `venv_create`, `pip_install` |
| **Security** | `password_generate`, `secret_scan`, `webhook_send` |
| **VM** | `detect_virtualization`, `hyperv_*`, `virtualbox_*`, `vmware_*`, `wsl_*`, `qemu_*` |
| **BIOS** | `bios_info`, `uefi_vars_list`, `uefi_var_read` |
| **Kernel** | `kernel_version`, `kernel_sysctl_*`, `kernel_modules_*`, `kernel_params` |

## Requirements

- Python 3.10+
- **Optional:** docker, kubectl, gh, git, nmap, terraform, aws, gcloud, redis-cli, whois, VirtualBox, VMware, Hyper-V, WSL, libvirt (for respective tools)

## Docs

Open [index.html](index.html) in a browser.

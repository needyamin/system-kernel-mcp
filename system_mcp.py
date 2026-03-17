"""SystemKernelMCP - Full control. Pentesting & automation. Run Cursor as Admin for max access."""
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path
from mcp.server.fastmcp import FastMCP

server = FastMCP(
    name="SystemKernelMCP",
    instructions="Full control MCP. No restrictions. Run Cursor as Administrator (Win) or root (Linux) for superadmin."
)

def _run(cmd: str, cwd: str | None = None, timeout: int = 300) -> tuple[str, str, int]:
    try:
        if sys.platform == "win32":
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        else:
            r = subprocess.run([os.environ.get("SHELL", "/bin/sh"), "-c", cmd], capture_output=True, text=True, cwd=cwd, timeout=timeout)
        return (r.stdout or "", r.stderr or "", r.returncode)
    except subprocess.TimeoutExpired:
        return ("", "Command timed out", -1)
    except Exception as e:
        return ("", str(e), -1)

def _processes(limit: int) -> str:
    if sys.platform == "win32":
        r = subprocess.run(["powershell", "-NoProfile", "-Command", f"Get-Process | Sort-Object CPU -Descending | Select-Object -First {limit} | Format-Table Id, ProcessName, CPU, WorkingSet -AutoSize | Out-String"], capture_output=True, text=True, timeout=30)
        return (r.stdout or r.stderr or "").strip() or "No output"
    out, _, _ = _run(f"ps aux --sort=-%cpu | head -n {limit + 1}")
    return out

def _path(p: str, base: str | None = None) -> Path:
    return (Path(base) / p).resolve() if base else Path(p).expanduser().resolve()

# --- Terminal & OS ---
@server.tool()
def execute_terminal_command(command: str, cwd: str | None = None, timeout: int = 300) -> str:
    """Run any terminal/shell command. Use for automation. Auto-detects Windows/Linux/macOS."""
    out, err, code = _run(command, cwd, timeout)
    return f"{out}\n[stderr]: {err}\n[exit: {code}]" if err else (out or f"Exit: {code}")

@server.tool()
def run_commands(commands: list[str], cwd: str | None = None) -> str:
    """Run multiple commands in sequence. Good for automation scripts."""
    results = []
    for cmd in commands[:50]:
        out, err, code = _run(cmd.strip(), cwd)
        results.append(f"$ {cmd}\n{out}{f'[stderr]: {err}' if err else ''}\n[exit: {code}]")
    return "\n---\n".join(results)

@server.tool()
def get_os_info() -> str:
    """Get system info: OS, kernel, architecture, Python, current directory."""
    p = platform.system().lower()
    os_name = "windows" if p == "windows" else ("darwin" if p == "darwin" else "linux")
    return f"OS: {os_name} | Kernel: {platform.release()} | Arch: {platform.machine()}\nPlatform: {platform.platform()}\nPython: {sys.version}\nCWD: {os.getcwd()}"

@server.tool()
def get_running_processes(limit: int = 50) -> str:
    """List running processes sorted by CPU usage. Useful for debugging."""
    return _processes(limit)

@server.tool()
def get_current_user() -> str:
    """Get current username and user ID."""
    out, _, _ = _run("whoami" if sys.platform != "win32" else "echo %USERNAME%")
    uid = os.getuid() if hasattr(os, "getuid") else "N/A"
    return f"User: {out.strip()}\nUID: {uid}"

# --- File operations ---
@server.tool()
def read_file(path: str, encoding: str = "utf-8") -> str:
    """Read file contents. Use for configs, logs, scripts."""
    try:
        p = _path(path)
        return p.read_text(encoding=encoding, errors="replace")
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def list_directory(path: str = ".", show_hidden: bool = False) -> str:
    """List files and folders in a directory."""
    try:
        p = _path(path)
        if not p.is_dir():
            return f"Not a directory: {path}"
        items = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        lines = []
        for i in items:
            if not show_hidden and i.name.startswith("."):
                continue
            prefix = "[DIR] " if i.is_dir() else ""
            try:
                size = i.stat().st_size if i.is_file() else 0
                lines.append(f"{prefix}{i.name} ({size} bytes)" if i.is_file() else f"{prefix}{i.name}/")
            except OSError:
                lines.append(f"{prefix}{i.name}")
        return "\n".join(lines) or "Empty"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def write_file(path: str, content: str, append: bool = False) -> str:
    """Write or append content to a file."""
    try:
        p = _path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a" if append else "w", encoding="utf-8") as f:
            f.write(content)
        return f"Written: {p} ({len(content)} chars)"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def file_exists(path: str) -> str:
    """Check if a file or directory exists."""
    try:
        p = _path(path)
        return f"Exists: {p.is_file() and 'file' or 'directory'}" if p.exists() else "Not found"
    except Exception as e:
        return f"Error: {e}"

# --- Network (pentesting) ---
@server.tool()
def ping_host(host: str, count: int = 4) -> str:
    """Ping a host to check if it's reachable."""
    cmd = f"ping -n {count} {host}" if sys.platform == "win32" else f"ping -c {count} {host}"
    out, err, code = _run(cmd, timeout=30)
    return out or err or f"Exit: {code}"

@server.tool()
def check_port(host: str, port: int, timeout: float = 3.0) -> str:
    """Check if a TCP port is open. Useful for port scanning."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return f"Port {port} on {host}: OPEN"
    except socket.timeout:
        return f"Port {port} on {host}: TIMEOUT (filtered/closed)"
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        return f"Port {port} on {host}: {type(e).__name__} - {e}"

@server.tool()
def get_network_info() -> str:
    """Get IP addresses and network interfaces."""
    if sys.platform == "win32":
        out, _, _ = _run("ipconfig")
    else:
        out, _, _ = _run("ip addr 2>/dev/null || ifconfig 2>/dev/null")
    return out or "No network info"

@server.tool()
def get_environment_vars(prefix: str = "") -> str:
    """List environment variables. Optional prefix to filter (e.g. PATH, HOME)."""
    env = dict(os.environ)
    if prefix:
        env = {k: v for k, v in env.items() if prefix.upper() in k.upper()}
    return "\n".join(f"{k}={v[:200]}..." if len(v) > 200 else f"{k}={v}" for k, v in sorted(env.items())[:50])

# --- Automation helpers ---
@server.tool()
def check_tool_installed(tool_name: str) -> str:
    """Check if a CLI tool is installed (e.g. nmap, python, git)."""
    out, err, _ = _run(f"which {tool_name}" if sys.platform != "win32" else f"where {tool_name}")
    found = bool(out.strip())
    return f"{tool_name}: {'Installed - ' + out.strip().split(chr(10))[0]}" if found else f"{tool_name}: Not found"

@server.tool()
def get_services(limit: int = 30) -> str:
    """List running services (Windows) or systemd units (Linux)."""
    if sys.platform == "win32":
        r = subprocess.run(["powershell", "-NoProfile", "-Command", f"Get-Service | Where-Object Status -eq Running | Select-Object -First {limit} | Format-Table Name, Status -AutoSize | Out-String"], capture_output=True, text=True, timeout=15)
        return (r.stdout or r.stderr or "").strip() or "No output"
    out, _, _ = _run(f"systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -n {limit + 5}" if os.path.exists("/run/systemd") else "echo 'Not systemd'")
    return out or "Run: systemctl (Linux)"

if __name__ == "__main__":
    server.run(transport="stdio")

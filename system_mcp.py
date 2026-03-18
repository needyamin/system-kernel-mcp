"""SystemKernelMCP - Full control. Pentesting & automation. Run Cursor as Admin for max access."""
import base64
import difflib
import hashlib
import json
import os
import re
import secrets
import sqlite3
import string
import urllib.parse
import uuid
import platform
import socket
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime
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

def _ps(cmd: str) -> tuple[str, str, int]:
    """Run PowerShell command."""
    esc = cmd.replace(chr(34), chr(92) + chr(34))
    return _run(f'powershell -NoProfile -Command "{esc}"')

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

# --- Unique/Advanced (no other MCP has these combined) ---
@server.tool()
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """DNS lookup. Record types: A, AAAA, MX, NS, TXT, CNAME."""
    out, err, _ = _run(f"nslookup -type={record_type} {domain}" if sys.platform == "win32" else f"dig +short {record_type} {domain} 2>/dev/null || nslookup -type={record_type} {domain}")
    return (out or err).strip() or "No result"

@server.tool()
def http_request(url: str, method: str = "GET", timeout: int = 10) -> str:
    """Fetch URL. Returns status, headers, body. Supports GET/POST."""
    try:
        req = urllib.request.Request(url, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")[:5000]
            return f"Status: {r.status}\nHeaders: {dict(r.headers)}\n\nBody:\n{body}"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def ssl_cert_info(host: str, port: int = 443) -> str:
    """Get SSL/TLS certificate details: issuer, expiry, subject."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return json.dumps(cert, indent=2)
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def list_listening_ports() -> str:
    """List all TCP ports listening on this machine."""
    if sys.platform == "win32":
        out, _, _ = _run("netstat -an | findstr LISTENING")
    else:
        out, _, _ = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    return out.strip() or "No output"

@server.tool()
def get_disk_usage(path: str = ".") -> str:
    """Disk space: total, used, free. Path for specific mount."""
    if sys.platform == "win32":
        out, _, _ = _run(f"Get-PSDrive -PSProvider FileSystem | Format-Table Name, Used, Free -AutoSize | Out-String")
    else:
        out, _, _ = _run(f"df -h {path}")
    return out.strip() or "No output"

@server.tool()
def get_system_uptime() -> str:
    """How long the system has been running."""
    if sys.platform == "win32":
        out, _, _ = _run("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
    else:
        out, _, _ = _run("uptime")
    return out.strip() or "N/A"

@server.tool()
def file_hash(path: str, algorithm: str = "sha256") -> str:
    """Compute file checksum. Algorithms: md5, sha1, sha256, sha512."""
    try:
        h = hashlib.new(algorithm)
        with open(_path(path), "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return f"{algorithm}: {h.hexdigest()}"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def base64_encode(text: str) -> str:
    """Encode string to Base64."""
    return base64.b64encode(text.encode()).decode()

@server.tool()
def base64_decode(data: str) -> str:
    """Decode Base64 string."""
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def decode_jwt(token: str) -> str:
    """Decode JWT token (header + payload). Does not verify signature."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return "Invalid JWT format"
        result = []
        for i, name in enumerate(["header", "payload"]):
            pad = parts[i] + "=" * (4 - len(parts[i]) % 4)
            decoded = base64.urlsafe_b64decode(pad)
            result.append(f"{name}: {json.dumps(json.loads(decoded), indent=2)}")
        return "\n\n".join(result)
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def get_scheduled_tasks(limit: int = 20) -> str:
    """List scheduled tasks (Windows Task Scheduler) or cron (Linux)."""
    if sys.platform == "win32":
        out, _, _ = _run(f"schtasks /query /fo LIST /v 2>nul | findstr /i \"TaskName NextRunTime\"")
    else:
        out, _, _ = _run("crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null | head -50")
    return (out or "No tasks").strip()[:2000]

@server.tool()
def get_arp_table() -> str:
    """ARP table: IP to MAC address mapping."""
    out, _, _ = _run("arp -a" if sys.platform == "win32" else "arp -n")
    return out.strip() or "No output"

@server.tool()
def get_routing_table() -> str:
    """Routing table: network routes."""
    out, _, _ = _run("route print" if sys.platform == "win32" else "ip route 2>/dev/null || route -n")
    return out.strip()[:3000] or "No output"

@server.tool()
def grep_files(path: str, pattern: str, file_pattern: str = "*") -> str:
    """Search for text/regex in files. Returns matching lines."""
    if sys.platform == "win32":
        out, _, _ = _run(f'Get-ChildItem -Path "{path}" -Recurse -Include {file_pattern} -ErrorAction SilentlyContinue | Select-String -Pattern "{pattern}" | Select-Object -First 50')
    else:
        out, _, _ = _run(f'grep -r -n "{pattern}" "{path}" 2>/dev/null | head -50')
    return (out or "No matches").strip()

@server.tool()
def diff_files(file1: str, file2: str) -> str:
    """Compare two files. Shows differences."""
    try:
        a = _path(file1).read_text(errors="replace").splitlines()
        b = _path(file2).read_text(errors="replace").splitlines()
        return "\n".join(difflib.unified_diff(a, b, fromfile=file1, tofile=file2))[:3000]
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def timestamp_convert(ts: str) -> str:
    """Convert Unix timestamp to readable date, or date string to timestamp."""
    try:
        if ts.isdigit():
            return datetime.fromtimestamp(int(ts)).isoformat()
        return str(int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()))
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def generate_uuid() -> str:
    """Generate a random UUID v4."""
    return str(uuid.uuid4())

# --- Docker ---
@server.tool()
def docker_ps(all_containers: bool = False) -> str:
    """List Docker containers. Set all_containers=True for stopped."""
    out, err, _ = _run(f"docker ps {'-a' if all_containers else ''}")
    return (out or err).strip() or "Docker not running or no containers"

@server.tool()
def docker_images() -> str:
    """List Docker images."""
    out, err, _ = _run("docker images")
    return (out or err).strip() or "Docker not running"

@server.tool()
def docker_logs(container: str, tail: int = 100) -> str:
    """Get logs from a container."""
    out, err, _ = _run(f"docker logs --tail {tail} {container}")
    return (out or err).strip() or "No logs"

@server.tool()
def docker_exec(container: str, command: str) -> str:
    """Run command inside a running container."""
    out, err, _ = _run(f"docker exec {container} {command}")
    return (out or err).strip() or f"Exit: {_}"

@server.tool()
def docker_inspect(container: str) -> str:
    """Inspect container details."""
    out, err, _ = _run(f"docker inspect {container}")
    return (out or err).strip()[:4000] or "Not found"

@server.tool()
def docker_stats() -> str:
    """Container CPU/memory stats."""
    out, err, _ = _run("docker stats --no-stream")
    return (out or err).strip() or "No containers"

@server.tool()
def docker_run(image: str, cmd: str = "", flags: str = "") -> str:
    """Run a new container. Example: image=nginx, cmd='', flags='-d -p 80:80'."""
    out, err, code = _run(f"docker run {flags} {image} {cmd}".strip())
    return (out or err).strip() or f"Exit: {code}"

@server.tool()
def docker_compose_up(path: str = ".", detach: bool = True) -> str:
    """Run docker-compose up. Path to dir with compose file."""
    flags = "-d" if detach else ""
    cwd = str(_path(path)) if path != "." else None
    out, err, _ = _run(f"docker compose up {flags}", cwd=cwd)
    return (out or err).strip()

@server.tool()
def docker_compose_down(path: str = ".") -> str:
    """Stop and remove docker-compose services."""
    cwd = str(_path(path)) if path != "." else None
    out, err, _ = _run("docker compose down", cwd=cwd)
    return (out or err).strip()

# --- Kubernetes ---
@server.tool()
def k8s_pods(namespace: str = "default") -> str:
    """List Kubernetes pods."""
    out, err, _ = _run(f"kubectl get pods -n {namespace}")
    return (out or err).strip() or "kubectl not configured or no pods"

@server.tool()
def k8s_services(namespace: str = "default") -> str:
    """List Kubernetes services."""
    out, err, _ = _run(f"kubectl get svc -n {namespace}")
    return (out or err).strip() or "No services"

@server.tool()
def k8s_deployments(namespace: str = "default") -> str:
    """List Kubernetes deployments."""
    out, err, _ = _run(f"kubectl get deployments -n {namespace}")
    return (out or err).strip() or "No deployments"

@server.tool()
def k8s_nodes() -> str:
    """List Kubernetes nodes."""
    out, err, _ = _run("kubectl get nodes")
    return (out or err).strip() or "kubectl not configured"

@server.tool()
def k8s_logs(pod: str, namespace: str = "default", tail: int = 100) -> str:
    """Get logs from a pod."""
    out, err, _ = _run(f"kubectl logs {pod} -n {namespace} --tail={tail}")
    return (out or err).strip() or "No logs"

@server.tool()
def k8s_describe(resource: str, name: str, namespace: str = "default") -> str:
    """Describe a K8s resource. Resource: pod, svc, deployment, etc."""
    out, err, _ = _run(f"kubectl describe {resource} {name} -n {namespace}")
    return (out or err).strip()[:5000] or "Not found"

@server.tool()
def k8s_exec(pod: str, command: str, namespace: str = "default") -> str:
    """Exec command in a pod."""
    out, err, _ = _run(f"kubectl exec {pod} -n {namespace} -- {command}")
    return (out or err).strip() or f"Exit: {_}"

@server.tool()
def k8s_apply(file: str) -> str:
    """Apply manifest file to cluster."""
    out, err, _ = _run(f"kubectl apply -f {file}")
    return (out or err).strip()

@server.tool()
def k8s_delete(resource: str, name: str, namespace: str = "default") -> str:
    """Delete a K8s resource."""
    out, err, _ = _run(f"kubectl delete {resource} {name} -n {namespace}")
    return (out or err).strip()

@server.tool()
def k8s_context() -> str:
    """Current kubectl context and cluster."""
    out, err, _ = _run("kubectl config current-context")
    ctx = (out or err).strip()
    out2, _, _ = _run("kubectl config view --minify -o jsonpath='{.contexts[0].context.cluster}'")
    return f"Context: {ctx}\nCluster: {(out2 or '').strip()}"

# --- VM / Virtualization ---
@server.tool()
def detect_virtualization() -> str:
    """Detect if running inside a VM (Hyper-V, VMware, VirtualBox, QEMU, etc)."""
    hints = []
    if sys.platform == "win32":
        out, _, _ = _run("systeminfo")
        for line in (out or "").splitlines():
            if "hyper-v" in line.lower() or "vmware" in line.lower() or "virtualbox" in line.lower() or "virtual" in line.lower():
                hints.append(line.strip())
        out2, _, _ = _run("wmic computersystem get model")
        if out2 and "Virtual" in out2:
            hints.append(f"Model: {out2.strip()}")
    else:
        out, _, _ = _run("systemd-detect-virt 2>/dev/null || cat /sys/class/dmi/id/sys_vendor 2>/dev/null")
        if out:
            hints.append(out.strip())
        out2, _, _ = _run("dmidecode -s system-manufacturer 2>/dev/null || true")
        if "vmware" in out2.lower() or "virtualbox" in out2.lower() or "qemu" in out2.lower():
            hints.append(out2.strip())
    return "\n".join(hints) if hints else "No VM detected (bare metal or unknown)"

@server.tool()
def hyperv_list_vms() -> str:
    """List Hyper-V virtual machines (Windows)."""
    out, err, _ = _ps("Get-VM | Format-Table Name, State, CPUUsage -AutoSize | Out-String")
    return (out or err).strip() or "Hyper-V not available or no VMs"

@server.tool()
def hyperv_vm_state(name: str) -> str:
    """Get Hyper-V VM state: Running, Off, etc."""
    out, err, _ = _ps(f"Get-VM -Name '{name}' | Select-Object Name, State | Format-List")
    return (out or err).strip() or "VM not found"

@server.tool()
def hyperv_start_vm(name: str) -> str:
    """Start a Hyper-V VM."""
    out, err, _ = _ps(f"Start-VM -Name '{name}'")
    return (out or err).strip()

@server.tool()
def hyperv_stop_vm(name: str) -> str:
    """Stop a Hyper-V VM."""
    out, err, _ = _ps(f"Stop-VM -Name '{name}' -Force")
    return (out or err).strip()

@server.tool()
def virtualbox_list_vms() -> str:
    """List VirtualBox VMs."""
    out, err, _ = _run("VBoxManage list vms")
    return (out or err).strip() or "VirtualBox not installed or no VMs"

@server.tool()
def virtualbox_vm_info(name: str) -> str:
    """Get VirtualBox VM info."""
    out, err, _ = _run(f'VBoxManage showvminfo "{name}"')
    return (out or err).strip()[:4000] or "VM not found"

@server.tool()
def virtualbox_start_vm(name: str, headless: bool = False) -> str:
    """Start VirtualBox VM. headless=True for no GUI."""
    mode = "-type headless" if headless else ""
    out, err, _ = _run(f'VBoxManage startvm "{name}" {mode}')
    return (out or err).strip()

@server.tool()
def virtualbox_stop_vm(name: str) -> str:
    """Stop VirtualBox VM (acpipowerbutton or poweroff)."""
    out, err, _ = _run(f'VBoxManage controlvm "{name}" poweroff')
    return (out or err).strip()

@server.tool()
def vmware_list_vms() -> str:
    """List VMware VMs (requires vmrun)."""
    out, err, _ = _run("vmrun list")
    return (out or err).strip() or "vmrun not found or no VMs"

@server.tool()
def vmware_run_in_vm(vmx_path: str, command: str, guest_user: str = "", guest_pass: str = "") -> str:
    """Run command inside VMware VM. vmx_path = path to .vmx file."""
    auth = f"-gu {guest_user} -gp {guest_pass}" if guest_user else ""
    out, err, _ = _run(f'vmrun -T ws runProgramInGuest "{vmx_path}" {auth} /bin/sh -c "{command.replace(chr(34), chr(39))}"')
    return (out or err).strip()

@server.tool()
def wsl_list() -> str:
    """List WSL distributions (Windows Subsystem for Linux)."""
    out, err, _ = _run("wsl -l -v")
    return (out or err).strip() or "WSL not installed"

@server.tool()
def wsl_run(distribution: str, command: str) -> str:
    """Run command in WSL. distribution: Ubuntu, Debian, etc or default."""
    dist = f"-d {distribution}" if distribution and distribution.lower() != "default" else ""
    out, err, _ = _run(f"wsl {dist} {command}")
    return (out or err).strip()

@server.tool()
def wsl_shutdown() -> str:
    """Shutdown all WSL instances."""
    out, err, _ = _run("wsl --shutdown")
    return (out or err).strip()

@server.tool()
def qemu_list_vms() -> str:
    """List QEMU/KVM VMs (Linux: virsh)."""
    out, err, _ = _run("virsh list --all")
    return (out or err).strip() or "libvirt/virsh not installed or no VMs"

@server.tool()
def qemu_vm_info(name: str) -> str:
    """Get QEMU/KVM VM info."""
    out, err, _ = _run(f"virsh dominfo {name}")
    return (out or err).strip() or "VM not found"

@server.tool()
def qemu_start_vm(name: str) -> str:
    """Start QEMU/KVM VM."""
    out, err, _ = _run(f"virsh start {name}")
    return (out or err).strip()

@server.tool()
def qemu_stop_vm(name: str) -> str:
    """Stop QEMU/KVM VM."""
    out, err, _ = _run(f"virsh shutdown {name}")
    return (out or err).strip()

# --- BIOS / UEFI ---
@server.tool()
def bios_info() -> str:
    """Get BIOS/UEFI info: vendor, version, date, serial."""
    if sys.platform == "win32":
        out, _, _ = _ps("Get-WmiObject Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber | Format-List")
        out2, _, _ = _ps("Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product | Format-List")
        return (out or "").strip() + "\n" + (out2 or "").strip()
    out, _, _ = _run("dmidecode -t bios 2>/dev/null || sudo dmidecode -t bios 2>/dev/null")
    return (out or "dmidecode not available").strip()[:2000]

@server.tool()
def uefi_vars_list() -> str:
    """List UEFI variables (Linux). Requires root for full list."""
    out, _, _ = _run("ls /sys/firmware/efi/efivars/ 2>/dev/null | head -50")
    return (out or "UEFI vars not available").strip()

@server.tool()
def uefi_var_read(name: str) -> str:
    """Read UEFI variable (Linux). Example: SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c."""
    try:
        data = _path(f"/sys/firmware/efi/efivars/{name}").read_bytes()
        return f"Raw ({len(data)} bytes): {data[:200].hex()}..."
    except Exception as e:
        return f"Error: {e}"

# --- Kernel ---
@server.tool()
def kernel_version() -> str:
    """Get kernel version and build info."""
    if sys.platform == "win32":
        out, _, _ = _run("ver")
        out2, _, _ = _ps("(Get-CimInstance Win32_OperatingSystem).Version")
        return f"Windows: {(out or '').strip()}\nVersion: {(out2 or '').strip()}"
    out, _, _ = _run("uname -a")
    return (out or "").strip()

@server.tool()
def kernel_sysctl_get(key: str) -> str:
    """Get kernel parameter (Linux sysctl). Example: kernel.hostname, net.ipv4.ip_forward."""
    out, err, _ = _run(f"sysctl -n {key} 2>/dev/null")
    return (out or err).strip() or "Key not found or not Linux"

@server.tool()
def kernel_sysctl_set(key: str, value: str) -> str:
    """Set kernel parameter (Linux). Requires root. Example: net.ipv4.ip_forward=1."""
    out, err, _ = _run(f"sysctl -w {key}={value}")
    return (out or err).strip()

@server.tool()
def kernel_sysctl_all() -> str:
    """List all kernel parameters (Linux)."""
    out, _, _ = _run("sysctl -a 2>/dev/null")
    return (out or "Not Linux").strip()[:5000]

@server.tool()
def kernel_modules_list() -> str:
    """List loaded kernel modules (Linux) or drivers (Windows)."""
    if sys.platform == "win32":
        out, _, _ = _ps("Get-WindowsDriver -Online | Select-Object Driver, ClassName -First 50 | Format-Table -AutoSize")
        return (out or "Requires admin").strip()
    out, _, _ = _run("lsmod | head -80")
    return (out or "").strip()

@server.tool()
def kernel_module_load(module: str) -> str:
    """Load kernel module (Linux). Requires root."""
    out, err, _ = _run(f"modprobe {module}")
    return (out or err).strip()

@server.tool()
def kernel_module_unload(module: str) -> str:
    """Unload kernel module (Linux). Requires root."""
    out, err, _ = _run(f"modprobe -r {module}")
    return (out or err).strip()

@server.tool()
def kernel_params() -> str:
    """Kernel boot parameters (Linux /proc/cmdline)."""
    try:
        return _path("/proc/cmdline").read_text().strip()
    except Exception:
        return "Not available (Windows or no /proc)"

# --- Git ---
@server.tool()
def git_status(path: str = ".") -> str:
    """Git status."""
    out, err, _ = _run("git status", cwd=str(_path(path)))
    return (out or err).strip()

@server.tool()
def git_clone(repo: str, path: str = ".") -> str:
    """Clone a git repository."""
    out, err, _ = _run(f"git clone {repo}", cwd=str(_path(path)))
    return (out or err).strip()

@server.tool()
def git_pull(path: str = ".") -> str:
    """Git pull."""
    out, err, _ = _run("git pull", cwd=str(_path(path)))
    return (out or err).strip()

@server.tool()
def git_push(path: str = ".", remote: str = "origin", branch: str = "") -> str:
    """Git push."""
    out, err, _ = _run(f"git push {remote} {branch}".strip(), cwd=str(_path(path)))
    return (out or err).strip()

@server.tool()
def git_commit(path: str, message: str, add_all: bool = True) -> str:
    """Git commit."""
    cwd = str(_path(path))
    if add_all:
        _run("git add -A", cwd=cwd)
    out, err, _ = _run(f'git commit -m "{message.replace(chr(34), chr(39))}"', cwd=cwd)
    return (out or err).strip()

@server.tool()
def git_log(path: str = ".", n: int = 20) -> str:
    """Git log."""
    out, err, _ = _run(f"git log -n {n} --oneline", cwd=str(_path(path)))
    return (out or err).strip()

@server.tool()
def git_branch(path: str = ".") -> str:
    """List git branches."""
    out, err, _ = _run("git branch -a", cwd=str(_path(path)))
    return (out or err).strip()

@server.tool()
def git_diff(path: str = ".", file: str = "") -> str:
    """Git diff."""
    out, err, _ = _run(f"git diff {file}".strip(), cwd=str(_path(path)))
    return (out or err).strip()[:4000]

# --- GitHub ---
@server.tool()
def gh_repos(user: str = "") -> str:
    """List GitHub repos (gh CLI). user=empty for self."""
    out, err, _ = _run(f"gh repo list {user} --limit 30" if user else "gh repo list --limit 30")
    return (out or err).strip() or "gh CLI not installed or not authenticated"

@server.tool()
def gh_repo_create(name: str, private: bool = False, description: str = "") -> str:
    """Create GitHub repo."""
    flags = "--private" if private else "--public"
    desc = f'--description "{description}"' if description else ""
    out, err, _ = _run(f"gh repo create {name} {flags} {desc}")
    return (out or err).strip()

@server.tool()
def gh_pr_list(repo: str = ".", state: str = "open") -> str:
    """List GitHub PRs."""
    out, err, _ = _run(f"gh pr list --state {state} --limit 20", cwd=str(_path(repo)) if repo != "." else None)
    return (out or err).strip()

@server.tool()
def gh_issue_list(repo: str = ".", state: str = "open") -> str:
    """List GitHub issues."""
    out, err, _ = _run(f"gh issue list --state {state} --limit 20", cwd=str(_path(repo)) if repo != "." else None)
    return (out or err).strip()

# --- Docker Hub ---
@server.tool()
def docker_login(username: str, password: str = "") -> str:
    """Docker login. Use token for password. Or run interactively with password empty."""
    if password:
        out, err, _ = _run(f'echo "{password}" | docker login -u {username} --password-stdin')
    else:
        out, err, _ = _run(f"docker login -u {username}")
    return (out or err).strip()

@server.tool()
def docker_push(image: str) -> str:
    """Push image to registry. Example: user/image:tag."""
    out, err, _ = _run(f"docker push {image}")
    return (out or err).strip()

@server.tool()
def docker_tag(source: str, target: str) -> str:
    """Tag image for registry push."""
    out, err, _ = _run(f"docker tag {source} {target}")
    return (out or err).strip()

# --- DevOps / Deployment ---
@server.tool()
def ssh_run(host: str, command: str, user: str = "") -> str:
    """Run command over SSH."""
    u = f"{user}@" if user else ""
    out, err, _ = _run(f'ssh -o StrictHostKeyChecking=no {u}{host} "{command.replace(chr(34), chr(39))}"')
    return (out or err).strip()

@server.tool()
def scp_copy(source: str, dest: str) -> str:
    """Copy file via SCP. Example: user@host:/path or local path."""
    out, err, _ = _run(f"scp -o StrictHostKeyChecking=no {source} {dest}")
    return (out or err).strip()

@server.tool()
def rsync_copy(source: str, dest: str, flags: str = "-avz") -> str:
    """Rsync files."""
    out, err, _ = _run(f"rsync {flags} {source} {dest}")
    return (out or err).strip()

@server.tool()
def curl_request(url: str, method: str = "GET", data: str = "") -> str:
    """Curl request."""
    d = f' -d "{data.replace(chr(34), chr(39))}"' if data else ""
    out, err, _ = _run(f'curl -s -X {method}{d} "{url}"')
    return (out or err).strip()[:5000]

# --- Dev / Encoding ---
@server.tool()
def url_encode(text: str) -> str:
    """URL encode."""
    return urllib.parse.quote(text)

@server.tool()
def url_decode(text: str) -> str:
    """URL decode."""
    return urllib.parse.unquote(text)

@server.tool()
def hex_encode(text: str) -> str:
    """Hex encode string."""
    return text.encode().hex()

@server.tool()
def hex_decode(hex_str: str) -> str:
    """Hex decode."""
    try:
        return bytes.fromhex(hex_str.replace(" ", "")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def json_format(text: str) -> str:
    """Format/validate JSON."""
    try:
        return json.dumps(json.loads(text), indent=2)
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def regex_test(pattern: str, text: str) -> str:
    """Test regex against text. Returns matches."""
    try:
        matches = re.findall(pattern, text)
        return str(matches) if matches else "No matches"
    except Exception as e:
        return f"Error: {e}"

# --- Pentesting / Hacking ---
@server.tool()
def nmap_scan(host: str, scan_type: str = "quick") -> str:
    """Nmap scan. Types: quick (-T4 -F), full (-p-), top100 (-top-ports 100)."""
    types = {"quick": "-T4 -F", "full": "-p-", "top100": "--top-ports 100"}
    flags = types.get(scan_type, "-T4 -F")
    out, err, _ = _run(f"nmap {flags} {host}", timeout=120)
    return (out or err).strip() or "nmap not installed"

@server.tool()
def port_scan_range(host: str, start: int, end: int) -> str:
    """Scan port range. Returns open ports."""
    out, err, _ = _run(f"nmap -p {start}-{end} {host}", timeout=60)
    return (out or err).strip()[:3000] or "nmap not installed"

@server.tool()
def hash_crack_check(hash: str, wordlist: str, algo: str = "sha256") -> str:
    """Check if hash matches any line in wordlist (hash each line, compare)."""
    try:
        target = hash.lower()
        with open(_path(wordlist)) as f:
            for line in f:
                h = hashlib.new(algo, line.strip().encode()).hexdigest()
                if h == target:
                    return f"Found: {line.strip()}"
        return "Not found in wordlist"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def hash_generate(text: str, algorithm: str = "sha256") -> str:
    """Generate hash of text."""
    return hashlib.new(algorithm, text.encode()).hexdigest()

@server.tool()
def subdomain_enum(domain: str) -> str:
    """Check common subdomains (www, mail, ftp, etc)."""
    subs = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "blog", "cdn"]
    results = []
    for s in subs:
        host = f"{s}.{domain}"
        try:
            socket.gethostbyname(host)
            results.append(f"{host}: exists")
        except socket.gaierror:
            results.append(f"{host}: NX")
    return "\n".join(results)

# --- Modern / Advanced ---
@server.tool()
def sqlite_query(db_path: str, query: str) -> str:
    """Run SQL on SQLite database."""
    try:
        conn = sqlite3.connect(_path(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query)
        rows = cur.fetchall()
        conn.close()
        return json.dumps([dict(r) for r in rows], indent=2) if rows else "No rows"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def whois_lookup(domain: str) -> str:
    """WHOIS lookup for domain."""
    out, err, _ = _run(f"whois {domain}", timeout=15)
    return (out or err).strip()[:3000] or "whois not installed"

@server.tool()
def graphql_query(url: str, query: str, variables: str = "{}") -> str:
    """Execute GraphQL query."""
    try:
        data = json.dumps({"query": query, "variables": json.loads(variables)})
        req = urllib.request.Request(url, data=data.encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode()[:5000]
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def ollama_chat(model: str, prompt: str, host: str = "http://localhost:11434") -> str:
    """Chat with local Ollama LLM."""
    try:
        data = json.dumps({"model": model, "prompt": prompt, "stream": False})
        req = urllib.request.Request(f"{host}/api/generate", data=data.encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read()).get("response", "No response")
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def openai_chat(model: str, prompt: str, api_key: str = "") -> str:
    """Chat with OpenAI API. Set OPENAI_API_KEY env or pass api_key."""
    key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return "Set OPENAI_API_KEY or pass api_key"
    try:
        data = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}]})
        req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=data.encode(), headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def password_generate(length: int = 16, symbols: bool = True) -> str:
    """Generate secure random password."""
    chars = string.ascii_letters + string.digits
    if symbols:
        chars += "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))

@server.tool()
def secret_scan(text: str) -> str:
    """Scan for potential secrets (API keys, tokens). Returns matches."""
    patterns = [
        (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key"),
        (r"(?i)(?:bearer)\s+([a-zA-Z0-9_\-\.]{20,})", "Bearer Token"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI Key"),
        (r"AKIA[0-9A-Z]{16}", "AWS Key"),
    ]
    found = []
    for pat, name in patterns:
        for m in re.finditer(pat, text):
            found.append(f"{name}: {m.group(1)[:20]}...")
    return "\n".join(found) if found else "No secrets detected"

@server.tool()
def webhook_send(url: str, payload: str, content_type: str = "application/json") -> str:
    """Send webhook (Discord, Slack, etc). Payload as JSON string."""
    try:
        data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": content_type}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return f"Status: {r.status}"
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def terraform_plan(path: str = ".") -> str:
    """Terraform plan."""
    out, err, _ = _run("terraform plan -no-color", cwd=str(_path(path)))
    return (out or err).strip()[:4000] or "terraform not installed"

@server.tool()
def terraform_apply(path: str = ".", auto_approve: bool = False) -> str:
    """Terraform apply."""
    flags = "-auto-approve" if auto_approve else ""
    out, err, _ = _run(f"terraform apply -no-color {flags}".strip(), cwd=str(_path(path)))
    return (out or err).strip()[:4000]

@server.tool()
def aws_cli(command: str) -> str:
    """Run AWS CLI. Example: s3 ls, ec2 describe-instances."""
    out, err, _ = _run(f"aws {command}")
    return (out or err).strip()[:4000] or "aws CLI not installed"

@server.tool()
def gcloud_cli(command: str) -> str:
    """Run gcloud CLI."""
    out, err, _ = _run(f"gcloud {command}")
    return (out or err).strip()[:4000] or "gcloud not installed"

@server.tool()
def redis_cli(command: str) -> str:
    """Run Redis CLI. Example: GET key, SET key val."""
    out, err, _ = _run(f"redis-cli {command}")
    return (out or err).strip() or "redis-cli not installed"

@server.tool()
def python_run(script: str, cwd: str = ".") -> str:
    """Run Python script. Path to .py file or inline code."""
    try:
        p = _path(script)
        if script.strip().endswith(".py") and p.is_file():
            out, err, _ = _run(f"python {p}", cwd=str(_path(cwd)))
        else:
            tmp = _path(f".mcp_{uuid.uuid4().hex[:8]}.py")
            tmp.write_text(script)
            out, err, _ = _run(f"python {tmp}", cwd=str(_path(cwd)))
            tmp.unlink(missing_ok=True)
        return (out or err).strip()
    except Exception as e:
        return f"Error: {e}"

@server.tool()
def venv_create(path: str = ".venv") -> str:
    """Create Python virtual environment."""
    out, err, _ = _run(f"python -m venv {path}")
    return (out or err).strip() or f"Created: {path}"

@server.tool()
def pip_install(packages: str, upgrade: bool = False) -> str:
    """Install pip packages. Comma-separated."""
    flags = "-U" if upgrade else ""
    out, err, _ = _run(f"pip install {flags} {packages}".strip())
    return (out or err).strip()

if __name__ == "__main__":
    if sys.stdin.isatty():
        print("SystemKernelMCP is a stdio server. Run from an MCP client (Cursor, Claude, Windsurf, etc.), not directly.")
        print("Add to your client's MCP config (e.g. .cursor/mcp.json) and restart.")
        sys.exit(0)
    server.run(transport="stdio")

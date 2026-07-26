import os
import json
import time
import threading
import subprocess
import sys
import winreg
import ctypes
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, Response

# 兼容 PyInstaller 打包后的运行路径
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(application_path, 'config.json')

app = Flask(__name__)

# --- 内存中的状态缓存 ---
current_blocked_ips = set()
last_mtime = 0

# --- 隐蔽配置 ---
RULE_PREFIX = "CoreNet-Diag-Block-"  # 极度枯燥的系统级规则名前缀
DEFAULT_CONFIG = {
    "web_port": 51883,               # 冷门高位端口，躲避常规扫描
    "admin_user": "admin",
    "admin_pass": "123456",          # 部署后请务必修改
    "blocked_ips": []
}

# --- 配置读写 ---
def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4)

# --- 防火墙底层操作 ---
def execute_cmd(cmd):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(cmd, shell=True, capture_output=True, text=False, startupinfo=startupinfo)
        return result.returncode == 0
    except Exception:
        return False

# ============ 新增：系统检查与自启动模块 ============

def get_app_path():
    """获取当前程序路径（兼容 PyInstaller 打包后）"""
    if getattr(sys, 'frozen', False):
        return sys.executable
    return os.path.abspath(sys.argv[0])

def check_firewall_status():
    """检查 Windows 防火墙三大配置文件是否全部开启"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             'Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress'],
            capture_output=True, text=True, startupinfo=startupinfo
        )
        if result.returncode == 0:
            profiles = json.loads(result.stdout)
            if not isinstance(profiles, list):
                profiles = [profiles]
            disabled = [p['Name'] for p in profiles if not p.get('Enabled')]
            if disabled:
                return False, f"防火墙未开启: {', '.join(disabled)}"
            return True, "防火墙正常"
    except Exception as e:
        return None, f"检测异常: {e}"

def ensure_self_port_allowed(port):
    """确保自身 Web 端口被防火墙放行（入站）。只按端口放行，不绑定程序，避免打包差异。"""
    rule_name = f"{RULE_PREFIX}Self-Allow-{port}"
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # 用 PowerShell 精确检查规则是否存在
    check_cmd = (
        f'powershell -WindowStyle Hidden -Command "'
        f'try {{ '
        f'    Get-NetFirewallRule -DisplayName \'{rule_name}\' -ErrorAction Stop | Out-Null; '
        f'    Write-Host \'EXISTS\' '
        f'}} catch {{ '
        f'    Write-Host \'NOTFOUND\' '
        f'}}"'
    )
    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, startupinfo=startupinfo)
    if 'EXISTS' in result.stdout:
        return True, "自身端口规则已存在"

    # 不存在则创建入站允许规则
    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" dir=in action=allow '
        f'protocol=tcp localport={port} '
        f'enable=yes'
    )
    success = execute_cmd(cmd)
    if success:
        return True, f"已放行端口 {port}"
    return False, "放行端口失败（可能需要管理员权限）"

def add_to_startup():
    """写入注册表 Run 键，实现开机自启动（用户级，无需管理员）"""
    try:
        app_path = get_app_path()
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "CoreNetDiagService", 0, winreg.REG_SZ, f'"{app_path}"')
        return True
    except Exception:
        return False

def remove_from_startup():
    """从注册表移除开机自启动"""
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "CoreNetDiagService")
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False

def is_in_startup():
    """检查是否已加入开机自启动"""
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, "CoreNetDiagService")
            return True
    except FileNotFoundError:
        return False

def set_console_icon(icon_path):
    """设置控制台窗口图标（仅对带控制台窗口生效，如未使用 --noconsole 打包）"""
    try:
        if not os.path.exists(icon_path):
            return False
        hicon = ctypes.windll.user32.LoadImageW(
            0, icon_path, 1, 0, 0, 0x00000010 | 0x00000040
        )
        if not hicon:
            return False
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.SendMessageW(hwnd, 0x80, 0, hicon)  # ICON_SMALL
            ctypes.windll.user32.SendMessageW(hwnd, 0x80, 1, hicon)  # ICON_BIG
        return True
    except Exception:
        return False

# 【修复1：确保进站和出站规则各自独立执行，完美拦截 iVMS】
def add_firewall_rule(ip):
    rule_name = f"{RULE_PREFIX}{ip}"
    cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}'
    in_success = execute_cmd(cmd_in)
    out_success = execute_cmd(cmd_out)
    return in_success and out_success

def remove_firewall_rule(ip):
    rule_name = f"{RULE_PREFIX}{ip}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    return execute_cmd(cmd)

# --- 核心：配置文件热更新与同步引擎 ---
def sync_firewall():
    global current_blocked_ips
    config = load_config()
    target_ips = set(config.get('blocked_ips', []))
    
    ips_to_add = target_ips - current_blocked_ips
    for ip in ips_to_add:
        add_firewall_rule(ip)
        
    ips_to_remove = current_blocked_ips - target_ips
    for ip in ips_to_remove:
        remove_firewall_rule(ip)
        
    current_blocked_ips = target_ips

def config_watcher():
    global last_mtime
    while True:
        try:
            if os.path.exists(CONFIG_FILE):
                mtime = os.path.getmtime(CONFIG_FILE)
                if mtime != last_mtime:
                    sync_firewall()
                    last_mtime = mtime
        except Exception:
            pass
        time.sleep(3)

# --- Web 鉴权与路由 ---
def check_auth(username, password):
    cfg = load_config()
    return username == cfg.get('admin_user') and password == cfg.get('admin_pass')

def authenticate():
    return Response('Access Denied.\n', 401, {'WWW-Authenticate': 'Basic realm="System Login"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@requires_auth
def index():
    cfg = load_config()
    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>CoreNet Diagnostic Service</title>
        <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5" style="max-width: 900px;">
            <h3 class="mb-4 text-secondary">⚙️ Core Network Diagnostics & Isolation</h3>
            
            <!-- 新增：系统状态面板 -->
            <div class="card mb-4 shadow-sm border-start border-4 border-dark">
                <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                    <span>System Status</span>
                    <button class="btn btn-sm btn-outline-light" onclick="refreshStatus()">Refresh</button>
                </div>
                <div class="card-body">
                    <div class="row text-center">
                        <div class="col-md-4 mb-2">
                            <small class="text-muted d-block">Firewall</small>
                            <span id="fwStatus" class="fw-bold">Checking...</span>
                        </div>
                        <div class="col-md-4 mb-2">
                            <small class="text-muted d-block">Self Port</small>
                            <span id="portStatus" class="fw-bold">Checking...</span>
                        </div>
                        <div class="col-md-4 mb-2">
                            <small class="text-muted d-block">Auto Startup</small>
                            <div class="d-flex align-items-center justify-content-center gap-2">
                                <span id="startupStatus" class="fw-bold">Checking...</span>
                                <button id="startupBtn" class="btn btn-sm btn-outline-primary" onclick="toggleStartup()">--</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card mb-4 shadow-sm">
                <div class="card-body">
                    <form id="addForm" class="d-flex">
                        <input type="text" id="ipInput" class="form-control me-2" placeholder="Target IPv4 Address" required>
                        <button type="submit" class="btn btn-secondary">Isolate (拦截)</button>
                    </form>
                </div>
            </div>
            
            <div class="card shadow-sm">
                <div class="card-header bg-secondary text-white">Isolated Endpoint List (隔离列表)</div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead class="table-light"><tr><th>IP Address</th><th class="text-end">Action</th></tr></thead>
                        <tbody>
                            {% for ip in ips %}
                            <tr>
                                <td class="align-middle text-danger fw-bold">{{ ip }}</td>
                                <td class="text-end"><button class="btn btn-sm btn-outline-success" onclick="unblockIp('{{ ip }}')">Restore (恢复)</button></td>
                            </tr>
                            {% else %}
                            <tr><td colspan="2" class="text-center text-muted py-3">No isolated endpoints</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <script>
            function refreshStatus() {
                fetch('/api/status').then(r => r.json()).then(data => {
                    const fwEl = document.getElementById('fwStatus');
                    fwEl.textContent = data.firewall_message;
                    fwEl.className = 'fw-bold ' + (data.firewall_enabled === true ? 'text-success' : (data.firewall_enabled === false ? 'text-danger' : 'text-warning'));
                    
                    const portEl = document.getElementById('portStatus');
                    portEl.textContent = data.self_port_message;
                    portEl.className = 'fw-bold ' + (data.self_port_allowed ? 'text-success' : 'text-warning');
                    
                    const stEl = document.getElementById('startupStatus');
                    stEl.textContent = data.startup_enabled ? 'Enabled' : 'Disabled';
                    
                    const btn = document.getElementById('startupBtn');
                    const action = data.startup_enabled ? 'disable' : 'enable';
                    btn.textContent = data.startup_enabled ? 'Disable' : 'Enable';
                    btn.className = 'btn btn-sm ' + (data.startup_enabled ? 'btn-outline-danger' : 'btn-outline-success');
                    btn.onclick = () => toggleStartup(action);
                });
            }
            function toggleStartup(action) {
                fetch('/api/startup', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action: action})
                }).then(r => r.json()).then(() => refreshStatus());
            }
            document.getElementById('addForm').addEventListener('submit', function(e) {
                e.preventDefault();
                fetch('/api/block', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: document.getElementById('ipInput').value.trim()})
                }).then(res => res.json()).then(data => location.reload());
            });
            function unblockIp(ip) {
                fetch('/api/unblock', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip})
                }).then(res => res.json()).then(data => location.reload());
            }
            document.addEventListener('DOMContentLoaded', refreshStatus);
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, ips=cfg.get('blocked_ips', []))

@app.route('/api/status')
@requires_auth
def status_api():
    cfg = load_config()
    fw_ok, fw_msg = check_firewall_status()
    port_ok, port_msg = ensure_self_port_allowed(cfg.get('web_port', 51883))
    return jsonify({
        "firewall_enabled": fw_ok,
        "firewall_message": fw_msg,
        "self_port_allowed": port_ok,
        "self_port_message": port_msg,
        "startup_enabled": is_in_startup()
    })

@app.route('/api/startup', methods=['POST'])
@requires_auth
def startup_api():
    action = request.json.get('action')
    if action == 'enable':
        success = add_to_startup()
    elif action == 'disable':
        success = remove_from_startup()
    else:
        return jsonify({"success": False, "error": "Invalid action"})
    return jsonify({"success": success, "enabled": is_in_startup()})

@app.route('/api/block', methods=['POST'])
@requires_auth
def block_api():
    cfg = load_config()
    ip = request.json.get('ip')
    if ip and ip not in cfg['blocked_ips']:
        cfg['blocked_ips'].append(ip)
        save_config(cfg)
    return jsonify({"success": True})

@app.route('/api/unblock', methods=['POST'])
@requires_auth
def unblock_api():
    cfg = load_config()
    ip = request.json.get('ip')
    if ip in cfg['blocked_ips']:
        cfg['blocked_ips'].remove(ip)
        save_config(cfg)
    return jsonify({"success": True})

if __name__ == '__main__':
    # 【修复2：使用 PowerShell 精准匹配并清理历史死规则】
    execute_cmd(f'powershell -WindowStyle Hidden -Command "Remove-NetFirewallRule -DisplayName \'{RULE_PREFIX}*\' -ErrorAction SilentlyContinue"')
    
    cfg = load_config()
    port = cfg.get('web_port', 51883)
    
    # 1. 启动时检查防火墙状态（仅打印，不阻断）
    fw_ok, fw_msg = check_firewall_status()
    print(f"[Firewall Check] {fw_msg}")
    
    # 2. 启动时自动确保自身端口被防火墙放行
    port_ok, port_msg = ensure_self_port_allowed(port)
    print(f"[Self Port Check] {port_msg}")
    
    # 3. 如果有 icon.ico，尝试设置控制台窗口图标
    icon_path = os.path.join(application_path, 'icon.ico')
    if os.path.exists(icon_path):
        if set_console_icon(icon_path):
            print(f"[Icon] Console icon set from {icon_path}")
    
    sync_firewall()
    
    # 启动文件监视器
    threading.Thread(target=config_watcher, daemon=True).start()
    
    # 禁用 werkzeug 默认的终端日志输出，追求极致静默
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

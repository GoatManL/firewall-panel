import os
import json
import time
import threading
import subprocess
import sys
import winreg
import ctypes
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response

# 兼容 PyInstaller 打包后的运行路径
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(application_path, 'config.json')

# 确保模板文件夹存在，适配 PyInstaller
template_dir = os.path.join(application_path, 'templates')
if not os.path.exists(template_dir):
    os.makedirs(template_dir)

app = Flask(__name__, template_folder=template_dir)

# --- 内存中的状态缓存 ---
current_blocked_ips = set()
last_mtime = 0

# --- 隐蔽配置 ---
RULE_PREFIX = "CoreNet-Diag-Block-"
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

# ============ 系统检查、防火墙自启与自启动模块 ============

def get_app_path():
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
            return True, "防火墙运行正常"
    except Exception as e:
        return None, f"防火墙状态检测异常: {e}"

def enable_firewall():
    """强制开启 Win10 系统的全部防火墙配置文件"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        cmd = (
            'powershell -WindowStyle Hidden -Command "'
            'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"'
        )
        execute_cmd(cmd)
    except Exception:
        pass

def ensure_self_port_allowed(port):
    """确保自身 Web 端口被防火墙放行"""
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
        return True, "端口放行规则已存在"

    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" dir=in action=allow '
        f'protocol=tcp localport={port} '
        f'enable=yes'
    )
    success = execute_cmd(cmd)
    if success:
        return True, f"已成功放行本机端口 {port}"
    return False, "放行端口失败 (可能是因为缺乏管理员权限)"

def add_to_startup():
    try:
        app_path = get_app_path()
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "CoreNetDiagService", 0, winreg.REG_SZ, f'"{app_path}"')
        return True
    except Exception:
        return False

def remove_from_startup():
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
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, "CoreNetDiagService")
            return True
    except FileNotFoundError:
        return False

def set_console_icon(icon_path):
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
            ctypes.windll.user32.SendMessageW(hwnd, 0x80, 0, hicon) 
            ctypes.windll.user32.SendMessageW(hwnd, 0x80, 1, hicon) 
            return True
    except Exception:
        return False

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
    return Response('拒绝访问，请提供正确的账号密码。\n', 401, {'WWW-Authenticate': 'Basic realm="System Login"'})

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
    return render_template('index.html', ips=cfg.get('blocked_ips', []))

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
        return jsonify({"success": False, "error": "无效的指令"})
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

@app.route('/api/restart', methods=['POST'])
@requires_auth
def restart_api():
    """执行无缝重启"""
    def do_restart():
        time.sleep(1) # 给前端留出返回 JSON 的时间
        subprocess.Popen([sys.executable] + sys.argv)
        os._exit(0)
    
    threading.Thread(target=do_restart, daemon=True).start()
    return jsonify({"success": True, "message": "服务即将重启"})

if __name__ == '__main__':
    # 启动前清理历史规则
    execute_cmd(f'powershell -WindowStyle Hidden -Command "Remove-NetFirewallRule -DisplayName \'{RULE_PREFIX}*\' -ErrorAction SilentlyContinue"')
    
    cfg = load_config()
    port = cfg.get('web_port', 51883)
    
    # 1. 检查防火墙并强制启动
    fw_ok, fw_msg = check_firewall_status()
    if fw_ok is False:
        print("[启动检查] 发现防火墙未完全开启，正在尝试强制开启...")
        enable_firewall()
        fw_ok, fw_msg = check_firewall_status()
    print(f"[防火墙状态] {fw_msg}")
    
    # 2. 确保本机端口被放行
    port_ok, port_msg = ensure_self_port_allowed(port)
    print(f"[本机端口] {port_msg}")
    
    # 3. 设置控制台图标
    icon_path = os.path.join(application_path, 'icon.ico')
    if os.path.exists(icon_path):
        if set_console_icon(icon_path):
            print(f"[界面图标] 成功加载 {icon_path}")
    
    # 初始化同步规则
    sync_firewall()
    
    # 启动文件监视器
    threading.Thread(target=config_watcher, daemon=True).start()
    
    # 禁用 werkzeug 默认日志，追求静默
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    print(f"[服务启动] 控制面板正在运行，监听端口: {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
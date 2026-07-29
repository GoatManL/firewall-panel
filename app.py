import os
import json
import time
import threading
import subprocess
import sys
import winreg
import ctypes
from functools import wraps
from flask import Flask, request, jsonify, Response, render_template

# 兼容 PyInstaller 的隐藏模板路径
if getattr(sys, 'frozen', False):
    application_path = sys._MEIPASS
    template_dir = os.path.join(application_path, 'templates')
else:
    application_path = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(application_path, 'templates')

CONFIG_FILE = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else application_path, 'config.json')

app = Flask(__name__, template_folder=template_dir)

current_blocked_ips = set()
last_mtime = 0

RULE_PREFIX = "CoreNet-Diag-Block-"
DEFAULT_CONFIG = {
    "web_port": 51883,
    "admin_user": "admin",
    "admin_pass": "123456",
    "blocked_ips": []
}

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

def execute_cmd(cmd):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(cmd, shell=True, capture_output=True, text=False, startupinfo=startupinfo)
        return result.returncode == 0
    except Exception:
        return False

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
                return False, f"未开启: {', '.join(disabled)}"
            return True, "运行正常"
    except Exception as e:
        return None, f"检测异常: {e}"

def enable_firewall():
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
        return True, "已放行"

    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" dir=in action=allow '
        f'protocol=tcp localport={port} '
        f'enable=yes'
    )
    success = execute_cmd(cmd)
    if success:
        return True, "已自动放行"
    return False, "放行失败"

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

def check_auth(username, password):
    cfg = load_config()
    return username == cfg.get('admin_user') and password == cfg.get('admin_pass')

def authenticate():
    return Response('未授权访问。\n', 401, {'WWW-Authenticate': 'Basic realm="System Login"'})

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
        return jsonify({"success": False, "error": "无效操作"})
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

# --- 新增：强制修复与重载防火墙 API ---
@app.route('/api/repair_firewall', methods=['POST'])
@requires_auth
def repair_firewall_api():
    try:
        enable_firewall()
        cfg = load_config()
        port = cfg.get('web_port', 51883)
        ensure_self_port_allowed(port)
        sync_firewall()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    execute_cmd(f'powershell -WindowStyle Hidden -Command "Remove-NetFirewallRule -DisplayName \'{RULE_PREFIX}*\' -ErrorAction SilentlyContinue"')
    
    cfg = load_config()
    port = cfg.get('web_port', 51883)
    
    fw_ok, _ = check_firewall_status()
    if not fw_ok:
        enable_firewall()
    
    ensure_self_port_allowed(port)
    sync_firewall()
    
    threading.Thread(target=config_watcher, daemon=True).start()
    
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
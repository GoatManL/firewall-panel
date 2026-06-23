import os
import json
import time
import threading
import subprocess
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, Response
import sys

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
        # 使用 CREATE_NO_WINDOW 标志隐藏闪烁的黑框 (针对打包后的环境)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=False, startupinfo=startupinfo)
        return result.returncode == 0
    except Exception:
        return False

def add_firewall_rule(ip):
    rule_name = f"{RULE_PREFIX}{ip}"
    cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}'
    return execute_cmd(cmd_in) or execute_cmd(cmd_out)

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
    for ip in ips_to_add: add_firewall_rule(ip)
        
    ips_to_remove = current_blocked_ips - target_ips
    for ip in ips_to_remove: remove_firewall_rule(ip)
        
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
    # 伪装后的 Web 界面
    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>CoreNet Diagnostic Service</title>
        <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5" style="max-width: 800px;">
            <h3 class="mb-4 text-secondary">⚙️ Core Network Diagnostics & Isolation</h3>
            
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
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, ips=cfg.get('blocked_ips', []))

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
    # 启动时清理一切历史残留规则，防止产生死规则
    execute_cmd(f'netsh advfirewall firewall delete rule name=all | findstr "{RULE_PREFIX}"')
    sync_firewall()
    
    # 启动文件监视器
    threading.Thread(target=config_watcher, daemon=True).start()
    
    cfg = load_config()
    # 禁用 werkzeug 默认的终端日志输出，追求极致静默
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app.run(host='0.0.0.0', port=cfg.get('web_port', 51883), debug=False, use_reloader=False)

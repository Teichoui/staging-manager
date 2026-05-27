#!/usr/bin/env python3
import os, json, subprocess, shutil, secrets, time, bcrypt, ssl, re, logging
from collections import defaultdict
from datetime import timedelta
from flask import Flask, jsonify, request, send_from_directory, session, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import urllib.request, urllib.error

# ── Paths ─────────────────────────────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.environ.get('STAGING_MANAGER_CONFIG_DIR', '/config')
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
SECRET_PATH = os.path.join(BASE_DIR, 'secret.key')
CERT_PATH = os.path.join(BASE_DIR, 'cert.pem')
KEY_PATH = os.path.join(BASE_DIR, 'key.pem')
LOG_PATH = os.environ.get('STAGING_MANAGER_LOG_PATH', os.path.join(BASE_DIR, 'app.log'))
APP_PORT = int(os.environ.get('STAGING_MANAGER_PORT', '7474'))
ENABLE_HTTPS = os.environ.get('STAGING_MANAGER_HTTPS', '').lower() in ('1', 'true', 'yes')
TRUST_PROXY = os.environ.get('STAGING_MANAGER_TRUST_PROXY', '').lower() in ('1', 'true', 'yes')
secure_cookie_env = os.environ.get('STAGING_MANAGER_SECURE_COOKIES')
SECURE_COOKIES = ENABLE_HTTPS if secure_cookie_env is None else secure_cookie_env.lower() in ('1', 'true', 'yes')

VIDEO_EXTENSIONS = {'.mkv', '.mp4', '.avi', '.m4v', '.mov', '.wmv', '.ts', '.m2ts'}

DEFAULT_CONFIG = {
    "username": "",
    "password_hash": "",
    "staging_tv": "/media/staging/tv-sonarr",
    "staging_movies": "/media/staging/radarr",
    "tv_library": "/mnt/tank/Media/TV",
    "movies_library": "/mnt/tank/Media/Movies",
    "staging_root": "/mnt/tank/Media/staging",
    "rclone_remote": "seedbox",
    "seedbox_tv_path": "/downloads/Done3/tv-sonarr",
    "seedbox_movies_path": "/downloads/Done3/radarr",
    "rclone_excludes": ["**/*.rar", "**/*.r[0-9][0-9]"],
    "rclone_transfers": 8,
    "sonarr_url": "http://host.docker.internal:30113",
    "sonarr_api_key": "",
    "radarr_url": "http://host.docker.internal:30025",
    "radarr_api_key": "",
    "truenas_url": "http://host.docker.internal",
    "truenas_api_key": "",
    "verify_tls": False,
    "app_uid": 568,
    "app_gid": 568,
    "session_timeout": 60,
    "max_login_attempts": 5,
    "lockout_minutes": 15
}

INT_CONFIG_FIELDS = {
    "rclone_transfers": (8, 1, 32),
    "app_uid": (568, 0, 2147483647),
    "app_gid": (568, 0, 2147483647),
    "session_timeout": (60, 5, 1440),
    "max_login_attempts": (5, 3, 20),
    "lockout_minutes": (15, 5, 60),
}

BOOL_CONFIG_FIELDS = {"verify_tls"}

os.makedirs(BASE_DIR, exist_ok=True)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger('staging-manager')

def parse_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('1', 'true', 'yes', 'on')
    return bool(value)

# ── Config helpers ────────────────────────────────────────────────────────────
def load_config():
    data = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            stored = json.load(f)
        data.update(stored)
    else:
        save_config(data)
    for key, (default, minimum, maximum) in INT_CONFIG_FIELDS.items():
        try:
            data[key] = max(minimum, min(maximum, int(data.get(key, default))))
        except (TypeError, ValueError):
            data[key] = default
    for key in BOOL_CONFIG_FIELDS:
        data[key] = parse_bool(data.get(key, DEFAULT_CONFIG[key]))
    if isinstance(data.get('rclone_excludes'), str):
        data['rclone_excludes'] = [x.strip() for x in data['rclone_excludes'].splitlines() if x.strip()]
    if not isinstance(data.get('rclone_excludes'), list):
        data['rclone_excludes'] = DEFAULT_CONFIG['rclone_excludes']
    return data

def save_config(data):
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(data, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)

def load_secret_key():
    os.makedirs(BASE_DIR, exist_ok=True)
    if os.environ.get('STAGING_MANAGER_SECRET_KEY'):
        return os.environ['STAGING_MANAGER_SECRET_KEY']
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, 'w') as f:
            f.write(secrets.token_hex(32))
        os.chmod(SECRET_PATH, 0o600)
    with open(SECRET_PATH) as f:
        return f.read().strip()

config = load_config()

# ── Flask setup ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=config.get('session_timeout', 60)),
)

limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri='memory://')
failed_attempts = defaultdict(list)

# ── Auth helpers ──────────────────────────────────────────────────────────────
def get_ip():
    if TRUST_PROXY and request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or 'unknown'

def is_locked(ip):
    cfg = load_config()
    cutoff = time.time() - cfg['lockout_minutes'] * 60
    failed_attempts[ip] = [t for t in failed_attempts[ip] if t > cutoff]
    return len(failed_attempts[ip]) >= cfg['max_login_attempts']

def is_authenticated():
    if not session.get('authenticated'):
        return False
    cfg = load_config()
    if time.time() - session.get('login_time', 0) > cfg['session_timeout'] * 60:
        session.clear()
        return False
    return True

def needs_setup():
    cfg = load_config()
    return not cfg.get('password_hash')

CSRF_EXEMPT = {'/api/login', '/api/setup'}

@app.before_request
def csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    if not request.path.startswith('/api/') or request.path in CSRF_EXEMPT:
        return None
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    expected = session.get('csrf_token')
    supplied = request.headers.get('X-CSRF-Token')
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    return None

@app.after_request
def security_headers(r):
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if ENABLE_HTTPS:
        r.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    r.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
    )
    return r

def safe_name(name):
    name = (name or '').strip()
    if not name or '/' in name or '\\' in name or '..' in name or name.startswith('.'):
        return None
    return name

def api_get(url, api_key):
    req = urllib.request.Request(url, headers={'X-Api-Key': api_key})
    ctx = ssl.create_default_context()
    if not load_config().get('verify_tls'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        return json.loads(r.read())

def truenas_api(method, endpoint, data=None):
    cfg = load_config()
    url = f"{cfg['truenas_url'].rstrip('/')}/api/v2.0/{endpoint}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method,
        headers={
            'Authorization': f"Bearer {cfg['truenas_api_key']}",
            'Content-Type': 'application/json'
        })
    ctx = ssl.create_default_context()
    if not cfg.get('verify_tls'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        raw = r.read()
        return json.loads(raw) if raw else None

def require_truenas_key(cfg):
    if not cfg.get('truenas_api_key'):
        raise ValueError('TrueNAS API key not configured in Settings')

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if needs_setup():
        return redirect('/setup')
    if not is_authenticated():
        return redirect('/login')
    return send_from_directory(APP_DIR, 'index.html')

@app.route('/login')
def login_page():
    if needs_setup():
        return redirect('/setup')
    if is_authenticated():
        return redirect('/')
    return send_from_directory(APP_DIR, 'login.html')

@app.route('/setup')
def setup_page():
    return send_from_directory(APP_DIR, 'setup.html')

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})

# ── Auth API ──────────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    ip = get_ip()
    if is_locked(ip):
        cfg = load_config()
        return jsonify({'success': False, 'error': f"Too many attempts. Try again in {cfg['lockout_minutes']} minutes."}), 429
    data = request.json or {}
    cfg = load_config()
    u_ok = secrets.compare_digest(data.get('username',''), cfg['username'])
    try:
        p_ok = bcrypt.checkpw(data.get('password','').encode(), cfg['password_hash'].encode())
    except:
        p_ok = False
    if u_ok and p_ok:
        failed_attempts[ip] = []
        session.clear()
        session['authenticated'] = True
        session['login_time'] = time.time()
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.permanent = True
        logger.info('login success ip=%s user=%s', ip, cfg['username'])
        return jsonify({'success': True})
    failed_attempts[ip].append(time.time())
    logger.warning('login failure ip=%s username=%s', ip, data.get('username',''))
    cfg = load_config()
    left = cfg['max_login_attempts'] - len(failed_attempts[ip])
    msg = 'Invalid credentials'
    if 0 < left <= 2:
        msg = f'Invalid credentials. {left} attempt(s) left.'
    elif left <= 0:
        msg = f'Locked out for {cfg["lockout_minutes"]} minutes.'
    return jsonify({'success': False, 'error': msg}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/setup', methods=['POST'])
def setup():
    if not needs_setup():
        return jsonify({'error': 'Already configured'}), 400
    data = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','')
    if not username or len(password) < 8:
        return jsonify({'error': 'Username required and password must be 8+ characters'}), 400
    cfg = load_config()
    cfg['username'] = username
    cfg['password_hash'] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    save_config(cfg)
    return jsonify({'success': True})

@app.route('/api/csrf')
def csrf_token():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    if not session.get('csrf_token'):
        session['csrf_token'] = secrets.token_urlsafe(32)
    return jsonify({'csrf_token': session['csrf_token']})

# ── Settings API ──────────────────────────────────────────────────────────────
@app.route('/api/settings', methods=['GET'])
def get_settings():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    # Never expose password hash
    safe = {k: v for k, v in cfg.items() if k != 'password_hash'}
    return jsonify(safe)

@app.route('/api/settings', methods=['POST'])
def save_settings():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    cfg = load_config()
    allowed = [k for k in DEFAULT_CONFIG if k not in ('username', 'password_hash')]
    for k in allowed:
        if k in data:
            if k in INT_CONFIG_FIELDS:
                default, minimum, maximum = INT_CONFIG_FIELDS[k]
                try:
                    cfg[k] = max(minimum, min(maximum, int(data[k])))
                except (TypeError, ValueError):
                    cfg[k] = default
            else:
                cfg[k] = data[k]
    for k in BOOL_CONFIG_FIELDS:
        if k in data:
            cfg[k] = parse_bool(data[k])
    if 'rclone_excludes' in data:
        raw_excludes = data.get('rclone_excludes') or []
        if isinstance(raw_excludes, str):
            cfg['rclone_excludes'] = [x.strip() for x in raw_excludes.splitlines() if x.strip()]
        elif isinstance(raw_excludes, list):
            cfg['rclone_excludes'] = [str(x).strip() for x in raw_excludes if str(x).strip()]
    # Handle password change
    if data.get('new_password'):
        if len(data['new_password']) < 8:
            return jsonify({'error': 'Password must be 8+ characters'}), 400
        cfg['password_hash'] = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt()).decode()
    if 'username' in data:
        username = str(data.get('username', '')).strip()
        if not username:
            return jsonify({'error': 'Username cannot be blank'}), 400
        cfg['username'] = username
    save_config(cfg)
    logger.info('settings updated user=%s', cfg.get('username', ''))
    return jsonify({'success': True})

# ── Staging API ───────────────────────────────────────────────────────────────
def has_video(path):
    try:
        for _, _, files in os.walk(path):
            if any(os.path.splitext(f)[1].lower() in VIDEO_EXTENSIONS for f in files):
                return True
        return False
    except:
        return False

def scan_staging(base, category):
    folders = []
    try:
        for name in sorted(os.listdir(base)):
            fp = os.path.join(base, name)
            if not os.path.isdir(fp):
                continue
            try:
                files = os.listdir(fp)
            except:
                files = []
            folders.append({'name': name, 'category': category,
                            'has_video': has_video(fp), 'file_count': len(files)})
    except:
        pass
    return folders

@app.route('/api/staging')
def get_staging():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    return jsonify({
        'tv': scan_staging(cfg['staging_tv'], 'tv'),
        'movies': scan_staging(cfg['staging_movies'], 'movies')
    })

@app.route('/api/sync', methods=['POST'])
def sync_folder():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    name = safe_name(data.get('name',''))
    category = data.get('category','tv')
    if not name or category not in ('tv','movies'):
        return jsonify({'error': 'Invalid request'}), 400
    if category == 'tv':
        remote = f"{cfg['rclone_remote']}:{cfg['seedbox_tv_path']}/{name}"
        local  = f"{cfg['staging_tv']}/{name}/"
    else:
        remote = f"{cfg['rclone_remote']}:{cfg['seedbox_movies_path']}/{name}"
        local  = f"{cfg['staging_movies']}/{name}/"
    cmd = ['rclone', 'copy', remote, local]
    for pattern in cfg.get('rclone_excludes', []):
        cmd.extend(['--exclude', pattern])
    cmd.extend(['--transfers', str(cfg.get('rclone_transfers', 8))])
    try:
        logger.info('sync start category=%s name=%s remote=%s local=%s', category, name, remote, local)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if r.returncode == 0:
            logger.info('sync success category=%s name=%s', category, name)
        else:
            logger.warning('sync failed category=%s name=%s stderr=%s', category, name, r.stderr.strip())
        return jsonify({'success': r.returncode==0, 'stdout': r.stdout, 'stderr': r.stderr})
    except subprocess.TimeoutExpired:
        logger.warning('sync timeout category=%s name=%s', category, name)
        return jsonify({'error': 'Timed out'}), 500
    except Exception as e:
        logger.exception('sync error category=%s name=%s', category, name)
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete', methods=['POST'])
def delete_folder():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    name = safe_name(data.get('name',''))
    category = data.get('category','tv')
    if not name or category not in ('tv','movies'):
        return jsonify({'error': 'Invalid request'}), 400
    base = cfg['staging_tv'] if category == 'tv' else cfg['staging_movies']
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(os.path.realpath(base) + os.sep):
        return jsonify({'error': 'Invalid path'}), 400
    if not os.path.exists(full):
        return jsonify({'error': 'Not found'}), 404
    try:
        shutil.rmtree(full)
        logger.info('deleted staging folder category=%s path=%s', category, full)
        return jsonify({'success': True})
    except Exception as e:
        logger.exception('delete failed category=%s path=%s', category, full)
        return jsonify({'error': str(e)}), 500

# ── Seedbox API ───────────────────────────────────────────────────────────────
@app.route('/api/seedbox')
def get_seedbox():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    category = request.args.get('category', 'tv')
    if category not in ('tv', 'movies'):
        return jsonify({'error': 'Invalid category'}), 400
    remote_path = cfg['seedbox_tv_path'] if category == 'tv' else cfg['seedbox_movies_path']
    remote = f"{cfg['rclone_remote']}:{remote_path}"
    try:
        r = subprocess.run(
            ['rclone', 'lsf', '--dirs-only', remote],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return jsonify({'error': r.stderr or 'rclone failed'}), 500
        folders = [f.rstrip('/') for f in r.stdout.strip().split('\n') if f.strip()]
        return jsonify({'folders': folders, 'category': category})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Errors API ────────────────────────────────────────────────────────────────
def parse_errors(log_entries):
    """Group and simplify Sonarr/Radarr log entries."""
    groups = defaultdict(list)
    for entry in log_entries:
        msg = entry.get('message', '')
        exc = entry.get('exception', '')
        combined = f'{msg}\n{exc}'
        time_str = entry.get('time', '')

        # Classify error type
        if 'Permission denied' in combined or 'UnauthorizedAccess' in combined or 'Access to the path' in combined:
            etype = 'permission'
            # Extract path
            match = re.search(r"(?:path|folder) '([^']+)'", combined, re.IGNORECASE)
            if not match:
                match = re.search(r"Access to the path '([^']+)'", combined)
            path = match.group(1) if match else 'unknown path'
            # Extract show name from path
            parts = path.split('/')
            show = parts[-3] if len(parts) >= 3 else path
            groups[('permission', show)].append({'path': path, 'time': time_str})
        elif 'No files found' in combined:
            etype = 'no_files'
            match = re.search(r'/staging/[^/]+/([^/\']+)', combined)
            folder = match.group(1) if match else msg[:80]
            groups[('no_files', folder)].append({'time': time_str})
        elif 'already exists' in combined.lower():
            etype = 'duplicate'
            groups[('duplicate', msg[:80])].append({'time': time_str})
        elif 'disk' in combined.lower() and 'space' in combined.lower():
            etype = 'disk_space'
            groups[('disk_space', 'Disk Space')].append({'time': time_str})
        else:
            groups[('other', msg[:80])].append({'time': time_str})

    result = []
    for (etype, label), items in sorted(groups.items(), key=lambda x: -len(x[1])):
        result.append({
            'type': etype,
            'label': label,
            'count': len(items),
            'latest': items[0]['time'] if items else '',
            'detail': items[0].get('path', '') if etype == 'permission' else ''
        })
    return result

@app.route('/api/errors')
def get_errors():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    result = {'sonarr': [], 'radarr': [], 'sonarr_error': None, 'radarr_error': None}

    # Sonarr
    try:
        logs = api_get(f"{cfg['sonarr_url']}/api/v3/log?page=1&pageSize=200&level=warn",
                       cfg['sonarr_api_key'])
        result['sonarr'] = parse_errors(logs.get('records', []))
    except Exception as e:
        result['sonarr_error'] = str(e)

    # Radarr
    try:
        logs = api_get(f"{cfg['radarr_url']}/api/v3/log?page=1&pageSize=200&level=warn",
                       cfg['radarr_api_key'])
        result['radarr'] = parse_errors(logs.get('records', []))
    except Exception as e:
        result['radarr_error'] = str(e)

    return jsonify(result)

@app.route('/api/rescan', methods=['POST'])
def rescan_series():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    app_type = data.get('app', 'sonarr')
    series_id = data.get('id')
    try:
        if app_type == 'sonarr':
            url = f"{cfg['sonarr_url']}/api/v3/command"
            key = cfg['sonarr_api_key']
            body = json.dumps({'name': 'RescanSeries', 'seriesId': series_id}).encode()
        else:
            url = f"{cfg['radarr_url']}/api/v3/command"
            key = cfg['radarr_api_key']
            body = json.dumps({'name': 'RescanMovie', 'movieId': series_id}).encode()
        req = urllib.request.Request(url, data=body, method='POST',
            headers={'X-Api-Key': key, 'Content-Type': 'application/json'})
        ctx = ssl.create_default_context()
        if not cfg.get('verify_tls'):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Permissions API ───────────────────────────────────────────────────────────
def posix_open_acl():
    rwx = {"READ": True, "WRITE": True, "EXECUTE": True}
    rx = {"READ": True, "WRITE": False, "EXECUTE": True}

    def ace(tag, perms, default=False):
        return {"tag": tag, "id": -1, "perms": perms, "default": default}

    return [
        ace("USER_OBJ", rwx),
        ace("GROUP_OBJ", rwx),
        ace("MASK", rwx),
        ace("OTHER", rx),
        ace("USER_OBJ", rwx, True),
        ace("GROUP_OBJ", rwx, True),
        ace("MASK", rwx, True),
        ace("OTHER", rx, True),
    ]

@app.route('/api/fix-permissions', methods=['POST'])
def fix_permissions():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    target = data.get('target', 'all')  # 'tv', 'movies', 'staging', 'all'

    paths = {
        'tv': cfg.get('tv_library', '/mnt/tank/Media/TV'),
        'movies': cfg.get('movies_library', '/mnt/tank/Media/Movies'),
        'staging': cfg.get('staging_root', '/mnt/tank/Media/staging')
    }

    targets = list(paths.values()) if target == 'all' else [paths.get(target)]
    targets = [t for t in targets if t]

    try:
        require_truenas_key(cfg)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    results = []
    for path in targets:
        try:
            payload = {
                "path": path,
                "uid": cfg.get('app_uid', 568),
                "gid": cfg.get('app_gid', 568),
                "acltype": "POSIX1E",
                "dacl": posix_open_acl(),
                "options": {
                    "stripacl": False,
                    "recursive": True,
                    "traverse": False,
                    "validate_effective_acl": False
                }
            }
            truenas_api('POST', 'filesystem/setacl', payload)
            logger.info('permission fix success target=%s path=%s uid=%s gid=%s',
                        target, path, cfg.get('app_uid', 568), cfg.get('app_gid', 568))
            results.append({'path': path, 'success': True})
        except Exception as e:
            logger.exception('permission fix failed target=%s path=%s', target, path)
            results.append({'path': path, 'success': False, 'error': str(e)})

    return jsonify({'results': results})

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    service = data.get('service')
    cfg = load_config()
    try:
        if service == 'sonarr':
            api_get(f"{cfg['sonarr_url']}/api/v3/system/status", cfg['sonarr_api_key'])
        elif service == 'radarr':
            api_get(f"{cfg['radarr_url']}/api/v3/system/status", cfg['radarr_api_key'])
        elif service == 'truenas':
            truenas_api('GET', 'system/info')
        elif service == 'rclone':
            r = subprocess.run(['rclone', 'lsd', f"{cfg['rclone_remote']}:/"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode != 0:
                return jsonify({'success': False, 'error': r.stderr})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    if ENABLE_HTTPS and not os.path.exists(CERT_PATH):
        print("Generating TLS certificate...")
        os.makedirs(BASE_DIR, exist_ok=True)
        subprocess.run([
            'openssl','req','-x509','-newkey','rsa:4096',
            '-keyout', KEY_PATH, '-out', CERT_PATH,
            '-days','3650','-nodes','-subj','/CN=staging-manager'
        ], check=True)
        os.chmod(KEY_PATH, 0o600)
        print(f"✓ Certificate saved")

    scheme = 'https' if ENABLE_HTTPS else 'http'
    print(f"\nStarting Media Manager on {scheme}://0.0.0.0:{APP_PORT}\n")
    if ENABLE_HTTPS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_PATH, KEY_PATH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        app.run(host='0.0.0.0', port=APP_PORT, ssl_context=ctx, debug=False)
    else:
        app.run(host='0.0.0.0', port=APP_PORT, debug=False)

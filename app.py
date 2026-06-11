#!/usr/bin/env python3
import os, json, subprocess, shutil, secrets, time, bcrypt, ssl, re, logging, ipaddress, threading, posixpath, sqlite3, xmlrpc.client  # nosec B404
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request, send_from_directory, session, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import urllib.request, urllib.error
from urllib.parse import urlparse

# ── Paths ─────────────────────────────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.environ.get('STAGING_MANAGER_CONFIG_DIR', '/config')
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
SECRET_PATH = os.path.join(BASE_DIR, 'secret.key')
SETUP_TOKEN_PATH = os.path.join(BASE_DIR, 'setup.token')
CERT_PATH = os.path.join(BASE_DIR, 'cert.pem')
KEY_PATH = os.path.join(BASE_DIR, 'key.pem')
LOG_PATH = os.environ.get('STAGING_MANAGER_LOG_PATH', os.path.join(BASE_DIR, 'app.log'))
DB_PATH = os.path.join(BASE_DIR, 'staging.db')
RCLONE_TORRENT_LOG = os.path.join(BASE_DIR, 'rclone-torrent.log')
APP_PORT = int(os.environ.get('STAGING_MANAGER_PORT', '7474'))
APP_HOST = os.environ.get('STAGING_MANAGER_HOST', '127.0.0.1')
ENABLE_HTTPS = os.environ.get('STAGING_MANAGER_HTTPS', '').lower() in ('1', 'true', 'yes')
TRUST_PROXY = os.environ.get('STAGING_MANAGER_TRUST_PROXY', '').lower() in ('1', 'true', 'yes')
secure_cookie_env = os.environ.get('STAGING_MANAGER_SECURE_COOKIES')
SECURE_COOKIES = ENABLE_HTTPS if secure_cookie_env is None else secure_cookie_env.lower() in ('1', 'true', 'yes')

VIDEO_EXTENSIONS = {'.mkv', '.mp4', '.avi', '.m4v', '.mov', '.wmv', '.ts', '.m2ts'}
RCLONE_BIN = os.environ.get('STAGING_MANAGER_RCLONE_BIN') or shutil.which('rclone') or 'rclone'
OPENSSL_BIN = os.environ.get('STAGING_MANAGER_OPENSSL_BIN') or shutil.which('openssl') or 'openssl'
CONTAINER_STAGING_ROOT = os.environ.get('STAGING_MANAGER_CONTAINER_STAGING_ROOT', '/media/staging')
TRUENAS_MEDIA_ROOT = os.environ.get('STAGING_MANAGER_TRUENAS_MEDIA_ROOT', '/mnt/tank/Media')
SEEDBOX_ALLOWED_ROOT = os.environ.get('STAGING_MANAGER_SEEDBOX_ALLOWED_ROOT', '/downloads/Done3')
ALLOWED_HOSTNAMES = {
    h.strip().lower() for h in os.environ.get(
        'STAGING_MANAGER_ALLOWED_HOSTS',
        'host.docker.internal,localhost,127.0.0.1,::1,truenas'
    ).split(',') if h.strip()
}

DEFAULT_CONFIG = {
    "username": "",
    "password_hash": "",  # nosec B105
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
    "cf_access_client_id": "",
    "cf_access_client_secret": "",
    "verify_tls": True,
    "app_uid": 568,
    "app_gid": 568,
    "session_timeout": 60,
    "max_login_attempts": 5,
    "lockout_minutes": 15,
    "ultracc_host": "",
    "ultracc_user": "",
    "ultracc_ssh_key": "/config/ultracc_id",
    "ultracc_ssh_password": "",
    "ultracc_ssh_port": 22,
    "rtorrent_url": "",
    "rtorrent_user": "",
    "rtorrent_password": "",
    "sync_interval": 5,
}

INT_CONFIG_FIELDS = {
    "rclone_transfers": (8, 1, 32),
    "app_uid": (568, 0, 2147483647),
    "app_gid": (568, 0, 2147483647),
    "session_timeout": (60, 5, 1440),
    "max_login_attempts": (5, 3, 20),
    "lockout_minutes": (15, 5, 60),
    "sync_interval": (5, 1, 60),
    "ultracc_ssh_port": (22, 1, 65535),
}

BOOL_CONFIG_FIELDS = {"verify_tls"}
SENSITIVE_CONFIG_FIELDS = {"sonarr_api_key", "radarr_api_key", "truenas_api_key", "cf_access_client_secret", "rtorrent_password", "ultracc_ssh_password"}
SECRET_MASK = "__STAGING_MANAGER_SECRET_SET__"  # nosec B105

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

def is_subpath(path, base):
    path_real = os.path.realpath(path)
    base_real = os.path.realpath(base)
    return path_real == base_real or path_real.startswith(base_real + os.sep)

def is_strict_subpath(path, base):
    path_real = os.path.realpath(path)
    base_real = os.path.realpath(base)
    return path_real.startswith(base_real + os.sep)

def validate_managed_path(path, base, field_name, strict=True):
    if not isinstance(path, str) or not path.strip():
        raise ValueError(f'{field_name} is required')
    path = path.strip().rstrip('/\\')
    ok = is_strict_subpath(path, base) if strict else is_subpath(path, base)
    if not ok:
        raise ValueError(f'{field_name} must stay under {base}')
    return path

def validate_service_url(url, field_name):
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f'{field_name} is required')
    url = url.strip().rstrip('/')
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'{field_name} must be an http(s) URL')
    host = parsed.hostname.lower()
    if host in ALLOWED_HOSTNAMES:
        return url
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f'{field_name} host is not allowed')
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise ValueError(f'{field_name} host is not allowed')
    if ip.is_private or ip.is_loopback or ip in ipaddress.ip_network('100.64.0.0/10'):
        return url
    raise ValueError(f'{field_name} host is not allowed')

def validate_username(username):
    if not isinstance(username, str):
        raise ValueError('Username must be a string')
    username = username.strip()
    if not username or len(username) > 64:
        raise ValueError('Username must be 1-64 characters')
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in username):
        raise ValueError('Username contains invalid characters')
    return username

def validate_rclone_remote_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', value.strip()):
        raise ValueError('rclone remote name may only contain letters, numbers, dot, underscore, and dash')
    return value.strip()

def validate_seedbox_path(path, field_name):
    if not isinstance(path, str) or not path.strip().startswith('/'):
        raise ValueError(f'{field_name} must be an absolute path')
    normalized = posixpath.normpath(path.strip())
    allowed = posixpath.normpath(SEEDBOX_ALLOWED_ROOT)
    if normalized == allowed or normalized.startswith(allowed + '/'):
        return normalized
    raise ValueError(f'{field_name} must stay under {SEEDBOX_ALLOWED_ROOT}')

def validate_external_url(url, field_name):
    """Like validate_service_url but allows external hostnames (e.g. rTorrent on a seedbox)."""
    if not isinstance(url, str) or not url.strip():
        return ''
    url = url.strip().rstrip('/')
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'{field_name} must be an http(s) URL')
    host = parsed.hostname.lower()
    # Block metadata/link-local IPs regardless
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValueError(f'{field_name} host is not allowed')
    except ValueError as exc:
        if 'host is not allowed' in str(exc):
            raise
    return url

def public_error(message='Operation failed'):
    return jsonify({'error': message}), 500

def get_setup_token():
    env_token = os.environ.get('STAGING_MANAGER_SETUP_TOKEN')
    if env_token:
        return env_token.strip()
    os.makedirs(BASE_DIR, exist_ok=True)
    if not os.path.exists(SETUP_TOKEN_PATH):
        token = secrets.token_urlsafe(32)
        with open(SETUP_TOKEN_PATH, 'w') as f:
            f.write(token)
        os.chmod(SETUP_TOKEN_PATH, 0o600)
        logger.warning('generated first-run setup token at %s', SETUP_TOKEN_PATH)
        print(f"\nFirst-run setup token written to {SETUP_TOKEN_PATH}\n")
    with open(SETUP_TOKEN_PATH) as f:
        return f.read().strip()

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
sync_lock = threading.Lock()
permission_lock = threading.Lock()

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
    timeout = 30 * 24 * 60 if session.get('remember_me') else cfg['session_timeout']
    if time.time() - session.get('login_time', 0) > timeout * 60:
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
    if not name or len(name) > 255 or '/' in name or '\\' in name or '..' in name or name.startswith('.'):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return None
    return name

def api_get(url, api_key):
    req = urllib.request.Request(url, headers={'X-Api-Key': api_key})
    ctx = ssl.create_default_context()
    if not load_config().get('verify_tls'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:  # nosec B310
        return json.loads(r.read())

def truenas_api(method, endpoint, data=None):
    cfg = load_config()
    base_url = validate_service_url(cfg['truenas_url'], 'truenas_url')
    url = f"{base_url}/api/v2.0/{endpoint}"
    body = json.dumps(data).encode() if data else None
    headers = {
        'Authorization': f"Bearer {cfg['truenas_api_key']}",
        'Content-Type': 'application/json'
    }
    if cfg.get('cf_access_client_id') and cfg.get('cf_access_client_secret'):
        headers['CF-Access-Client-Id'] = cfg['cf_access_client_id']
        headers['CF-Access-Client-Secret'] = cfg['cf_access_client_secret']
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    ctx = ssl.create_default_context()
    if not cfg.get('verify_tls'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:  # nosec B310
        raw = r.read()
        return json.loads(raw) if raw else None

def require_truenas_key(cfg):
    if not cfg.get('truenas_api_key'):
        raise ValueError('TrueNAS API key not configured in Settings')

# ── SQLite DB ─────────────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS synced_torrents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            torrent_hash TEXT UNIQUE NOT NULL,
            torrent_name TEXT NOT NULL,
            remote_path TEXT NOT NULL,
            local_path TEXT NOT NULL,
            category TEXT DEFAULT 'tv',
            synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'copied'
        )''')
        conn.commit()

# ── rTorrent XMLRPC client ────────────────────────────────────────────────────
def query_rtorrent(cfg):
    url = cfg.get('rtorrent_url', '').strip()
    user = cfg.get('rtorrent_user', '').strip()
    password = cfg.get('rtorrent_password', '').strip()
    if not url or not user or not password:
        raise ValueError('rTorrent URL, username, and password are required in Settings')
    parsed = urlparse(url)
    auth_url = f"{parsed.scheme}://{user}:{password}@{parsed.netloc}{parsed.path}"
    ctx = ssl.create_default_context()
    if not cfg.get('verify_tls'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    transport = xmlrpc.client.SafeTransport(context=ctx)
    client = xmlrpc.client.ServerProxy(auth_url, transport=transport)
    results = client.d.multicall2('', 'complete',
        'd.hash=', 'd.name=', 'd.base_path=', 'd.complete=', 'd.custom1=')
    completed = []
    for torrent in results:
        hash_, name, base_path, complete, label = torrent
        if complete == 1:
            completed.append({
                'hash': hash_,
                'name': name,
                'base_path': base_path,
                'label': (label or '').lower(),
            })
    return completed

# ── Torrent sync engine ───────────────────────────────────────────────────────
torrent_sync_state = {
    'status': 'idle',       # idle | syncing | error
    'last_sync': None,      # unix timestamp
    'last_error': None,     # string
    'active_torrent': None, # torrent name currently copying
}
torrent_sync_lock = threading.Lock()

def run_torrent_sync():
    if not torrent_sync_lock.acquire(blocking=False):
        logger.info('torrent sync skipped: already running')
        return
    torrent_sync_state['status'] = 'syncing'
    torrent_sync_state['last_error'] = None
    try:
        cfg = load_config()
        torrents = query_rtorrent(cfg)
        logger.info('torrent sync: %d completed torrents on seedbox', len(torrents))

        with sqlite3.connect(DB_PATH) as conn:
            for t in torrents:
                already = conn.execute(
                    'SELECT id FROM synced_torrents WHERE torrent_hash=?', (t['hash'],)
                ).fetchone()
                if already:
                    continue

                # Route by rTorrent label: anything with 'radarr' → movies, else tv
                if 'radarr' in t['label']:
                    category = 'movies'
                    local_base = cfg['staging_movies']
                else:
                    category = 'tv'
                    local_base = cfg['staging_tv']

                local_path = f"{local_base}/{t['name']}"
                torrent_sync_state['active_torrent'] = t['name']

                host = cfg.get('ultracc_host', '').strip()
                user = cfg.get('ultracc_user', '').strip()
                port = cfg.get('ultracc_ssh_port', 22)
                key_file = cfg.get('ultracc_ssh_key', '').strip()
                password = cfg.get('ultracc_ssh_password', '').strip()
                remote_path = t['base_path']

                if not host or not user:
                    logger.warning('torrent sync: ultracc host/user not configured')
                    break

                # Prefer key auth; fall back to password auth
                use_key = key_file and os.path.exists(key_file)
                if use_key:
                    sftp_src = f':sftp,host={host},user={user},port={port},key_file={key_file}:{remote_path}'
                elif password:
                    obs = subprocess.run([RCLONE_BIN, 'obscure', password],
                                         capture_output=True, text=True)  # nosec B603
                    if obs.returncode != 0:
                        logger.warning('torrent sync: rclone obscure failed')
                        break
                    sftp_src = f':sftp,host={host},user={user},port={port},pass={obs.stdout.strip()}:{remote_path}'
                else:
                    logger.warning('torrent sync: no SSH key or password configured')
                    break
                cmd = [RCLONE_BIN, 'copy', sftp_src, local_path,
                       '--log-file', RCLONE_TORRENT_LOG, '--log-level', 'INFO',
                       '--stats', '5s', '--stats-log-level', 'INFO',
                       '--transfers', str(cfg.get('rclone_transfers', 8))]
                for pattern in cfg.get('rclone_excludes', []):
                    cmd.extend(['--exclude', pattern])

                logger.info('torrent sync copying: name=%s → %s', t['name'], local_path)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # nosec B603

                if result.returncode == 0:
                    conn.execute(
                        'INSERT OR IGNORE INTO synced_torrents '
                        '(torrent_hash, torrent_name, remote_path, local_path, category) '
                        'VALUES (?,?,?,?,?)',
                        (t['hash'], t['name'], remote_path, local_path, category)
                    )
                    conn.commit()
                    logger.info('torrent sync success: %s', t['name'])
                else:
                    logger.warning('torrent sync failed: name=%s stderr=%s',
                                   t['name'], result.stderr[:500])

        torrent_sync_state['last_sync'] = time.time()
        torrent_sync_state['status'] = 'idle'
        torrent_sync_state['active_torrent'] = None

    except Exception as e:
        logger.exception('torrent sync error: %s', e)
        torrent_sync_state['status'] = 'error'
        torrent_sync_state['last_error'] = str(e)
        torrent_sync_state['active_torrent'] = None
    finally:
        torrent_sync_lock.release()

# ── Scheduler ─────────────────────────────────────────────────────────────────
scheduler = BackgroundScheduler(daemon=True)

def reschedule_sync(interval_minutes):
    interval_minutes = max(1, min(60, int(interval_minutes)))
    if scheduler.get_job('torrent_sync'):
        scheduler.remove_job('torrent_sync')
    scheduler.add_job(run_torrent_sync, 'interval', minutes=interval_minutes,
                      id='torrent_sync', replace_existing=True)

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
    if not needs_setup():
        return redirect('/login')
    get_setup_token()
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
    data = request.json if isinstance(request.json, dict) else {}
    username = data.get('username', '')
    password = data.get('password', '')
    if not isinstance(username, str) or not isinstance(password, str):
        failed_attempts[ip].append(time.time())
        logger.warning('login failure ip=%s username=%s', ip, str(username)[:64])
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    cfg = load_config()
    u_ok = secrets.compare_digest(username, cfg['username'])
    try:
        p_ok = bcrypt.checkpw(password.encode(), cfg['password_hash'].encode())
    except:
        p_ok = False
    if u_ok and p_ok:
        failed_attempts[ip] = []
        remember = bool(data.get('remember_me'))
        session.clear()
        session['authenticated'] = True
        session['login_time'] = time.time()
        session['csrf_token'] = secrets.token_urlsafe(32)
        session['remember_me'] = remember
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=30) if remember else timedelta(minutes=load_config().get('session_timeout', 60))
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
@limiter.limit("5 per minute")
def setup():
    if not needs_setup():
        return jsonify({'error': 'Already configured'}), 400
    data = request.json or {}
    supplied_token = data.get('setup_token') or request.headers.get('X-Setup-Token') or ''
    expected_token = get_setup_token()
    if not supplied_token or not secrets.compare_digest(str(supplied_token), expected_token):
        logger.warning('setup token failure ip=%s', get_ip())
        return jsonify({'error': 'Invalid setup token'}), 403
    try:
        username = validate_username(data.get('username',''))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
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
    for key in SENSITIVE_CONFIG_FIELDS:
        if safe.get(key):
            safe[key] = SECRET_MASK
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
            if k in SENSITIVE_CONFIG_FIELDS and data[k] == SECRET_MASK:
                continue
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
    try:
        cfg['staging_tv'] = validate_managed_path(cfg['staging_tv'], CONTAINER_STAGING_ROOT, 'staging_tv')
        cfg['staging_movies'] = validate_managed_path(cfg['staging_movies'], CONTAINER_STAGING_ROOT, 'staging_movies')
        cfg['tv_library'] = validate_managed_path(cfg['tv_library'], TRUENAS_MEDIA_ROOT, 'tv_library')
        cfg['movies_library'] = validate_managed_path(cfg['movies_library'], TRUENAS_MEDIA_ROOT, 'movies_library')
        cfg['staging_root'] = validate_managed_path(cfg['staging_root'], TRUENAS_MEDIA_ROOT, 'staging_root')
        cfg['sonarr_url'] = validate_service_url(cfg['sonarr_url'], 'sonarr_url')
        cfg['radarr_url'] = validate_service_url(cfg['radarr_url'], 'radarr_url')
        cfg['truenas_url'] = validate_service_url(cfg['truenas_url'], 'truenas_url')
        cfg['rclone_remote'] = validate_rclone_remote_name(cfg['rclone_remote'])
        cfg['seedbox_tv_path'] = validate_seedbox_path(cfg['seedbox_tv_path'], 'seedbox_tv_path')
        cfg['seedbox_movies_path'] = validate_seedbox_path(cfg['seedbox_movies_path'], 'seedbox_movies_path')
        cfg['rtorrent_url'] = validate_external_url(cfg.get('rtorrent_url', ''), 'rtorrent_url')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    # Handle password change
    if data.get('new_password'):
        if len(data['new_password']) < 8:
            return jsonify({'error': 'Password must be 8+ characters'}), 400
        cfg['password_hash'] = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt()).decode()
    if 'username' in data:
        try:
            cfg['username'] = validate_username(data.get('username', ''))
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
    save_config(cfg)
    reschedule_sync(cfg.get('sync_interval', 5))
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
    except Exception as e:
        logger.debug('staging scan skipped base=%s error=%s', base, e)
    return folders

def get_staging_base(cfg, category):
    key = 'staging_tv' if category == 'tv' else 'staging_movies'
    return validate_managed_path(cfg[key], CONTAINER_STAGING_ROOT, key)

@app.route('/api/staging')
def get_staging():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    try:
        tv_base = get_staging_base(cfg, 'tv')
        movies_base = get_staging_base(cfg, 'movies')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'tv': scan_staging(tv_base, 'tv'), 'movies': scan_staging(movies_base, 'movies')})

@app.route('/api/sync', methods=['POST'])
@limiter.limit("6 per minute")
def sync_folder():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    name = safe_name(data.get('name',''))
    category = data.get('category','tv')
    if not name or category not in ('tv','movies'):
        return jsonify({'error': 'Invalid request'}), 400
    try:
        remote_name = validate_rclone_remote_name(cfg['rclone_remote'])
        seedbox_tv_path = validate_seedbox_path(cfg['seedbox_tv_path'], 'seedbox_tv_path')
        seedbox_movies_path = validate_seedbox_path(cfg['seedbox_movies_path'], 'seedbox_movies_path')
        staging_base = get_staging_base(cfg, category)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if not sync_lock.acquire(blocking=False):
        return jsonify({'error': 'A sync is already running'}), 429
    if category == 'tv':
        remote = f"{remote_name}:{seedbox_tv_path}/{name}"
    else:
        remote = f"{remote_name}:{seedbox_movies_path}/{name}"
    local  = f"{staging_base}/{name}/"
    cmd = [RCLONE_BIN, 'copy', remote, local]
    for pattern in cfg.get('rclone_excludes', []):
        cmd.extend(['--exclude', pattern])
    cmd.extend(['--transfers', str(cfg.get('rclone_transfers', 8))])
    try:
        logger.info('sync start category=%s name=%s remote=%s local=%s', category, name, remote, local)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # nosec B603
        if r.returncode == 0:
            logger.info('sync success category=%s name=%s', category, name)
        else:
            logger.warning('sync failed category=%s name=%s stderr=%s', category, name, r.stderr.strip())
        return jsonify({'success': r.returncode==0, 'message': 'Sync finished' if r.returncode == 0 else 'Sync failed'})
    except subprocess.TimeoutExpired:
        logger.warning('sync timeout category=%s name=%s', category, name)
        return jsonify({'error': 'Timed out'}), 500
    except Exception as e:
        logger.exception('sync error category=%s name=%s', category, name)
        return public_error()
    finally:
        sync_lock.release()

@app.route('/api/delete', methods=['POST'])
@limiter.limit("30 per minute")
def delete_folder():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    name = safe_name(data.get('name',''))
    category = data.get('category','tv')
    if not name or category not in ('tv','movies'):
        return jsonify({'error': 'Invalid request'}), 400
    try:
        base = get_staging_base(cfg, category)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
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
        return public_error('Delete failed')

# ── Seedbox API ───────────────────────────────────────────────────────────────
@app.route('/api/seedbox')
@limiter.limit("20 per minute")
def get_seedbox():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    category = request.args.get('category', 'tv')
    if category not in ('tv', 'movies'):
        return jsonify({'error': 'Invalid category'}), 400
    try:
        remote_name = validate_rclone_remote_name(cfg['rclone_remote'])
        remote_path = validate_seedbox_path(
            cfg['seedbox_tv_path'] if category == 'tv' else cfg['seedbox_movies_path'],
            'seedbox_path'
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    remote = f"{remote_name}:{remote_path}"
    try:
        r = subprocess.run(
            [RCLONE_BIN, 'lsf', '--dirs-only', remote],
            capture_output=True, text=True, timeout=30
        )  # nosec B603
        if r.returncode != 0:
            logger.warning('seedbox browse failed category=%s stderr=%s', category, r.stderr.strip())
            return public_error('Seedbox browse failed')
        folders = [f.rstrip('/') for f in r.stdout.strip().split('\n') if f.strip()]
        return jsonify({'folders': folders, 'category': category})
    except Exception as e:
        logger.exception('seedbox browse error category=%s', category)
        return public_error('Seedbox browse failed')

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
@limiter.limit("20 per minute")
def get_errors():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    result = {'sonarr': [], 'radarr': [], 'sonarr_error': None, 'radarr_error': None}

    # Sonarr
    try:
        sonarr_url = validate_service_url(cfg['sonarr_url'], 'sonarr_url')
        logs = api_get(f"{sonarr_url}/api/v3/log?page=1&pageSize=200&level=warn",
                       cfg['sonarr_api_key'])
        result['sonarr'] = parse_errors(logs.get('records', []))
    except Exception as e:
        logger.warning('sonarr log fetch failed: %s', e)
        result['sonarr_error'] = 'Unable to fetch Sonarr logs'

    # Radarr
    try:
        radarr_url = validate_service_url(cfg['radarr_url'], 'radarr_url')
        logs = api_get(f"{radarr_url}/api/v3/log?page=1&pageSize=200&level=warn",
                       cfg['radarr_api_key'])
        result['radarr'] = parse_errors(logs.get('records', []))
    except Exception as e:
        logger.warning('radarr log fetch failed: %s', e)
        result['radarr_error'] = 'Unable to fetch Radarr logs'

    return jsonify(result)

@app.route('/api/rescan', methods=['POST'])
@limiter.limit("20 per minute")
def rescan_series():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json if isinstance(request.json, dict) else {}
    app_type = data.get('app', 'sonarr')
    if app_type not in ('sonarr', 'radarr'):
        return jsonify({'error': 'Invalid app'}), 400
    raw_id = data.get('id')
    if isinstance(raw_id, bool):
        return jsonify({'error': 'id must be a positive integer'}), 400
    try:
        series_id = int(raw_id)
        if series_id <= 0:
            raise ValueError('id must be positive')
    except (TypeError, ValueError):
        return jsonify({'error': 'id must be a positive integer'}), 400
    try:
        if app_type == 'sonarr':
            url = f"{validate_service_url(cfg['sonarr_url'], 'sonarr_url')}/api/v3/command"
            key = cfg['sonarr_api_key']
            body = json.dumps({'name': 'RescanSeries', 'seriesId': series_id}).encode()
        else:
            url = f"{validate_service_url(cfg['radarr_url'], 'radarr_url')}/api/v3/command"
            key = cfg['radarr_api_key']
            body = json.dumps({'name': 'RescanMovie', 'movieId': series_id}).encode()
        req = urllib.request.Request(url, data=body, method='POST',
            headers={'X-Api-Key': key, 'Content-Type': 'application/json'})
        ctx = ssl.create_default_context()
        if not cfg.get('verify_tls'):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:  # nosec B310
            return jsonify({'success': True})
    except Exception as e:
        logger.warning('rescan failed app=%s id=%s error=%s', app_type, series_id, e)
        return public_error('Rescan failed')

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
@limiter.limit("3 per hour")
def fix_permissions():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg = load_config()
    data = request.json or {}
    target = data.get('target', 'all')  # 'tv', 'movies', 'staging', 'all'

    try:
        paths = {
            'tv': validate_managed_path(cfg.get('tv_library', '/mnt/tank/Media/TV'), TRUENAS_MEDIA_ROOT, 'tv_library'),
            'movies': validate_managed_path(cfg.get('movies_library', '/mnt/tank/Media/Movies'), TRUENAS_MEDIA_ROOT, 'movies_library'),
            'staging': validate_managed_path(cfg.get('staging_root', '/mnt/tank/Media/staging'), TRUENAS_MEDIA_ROOT, 'staging_root')
        }
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    targets = list(paths.values()) if target == 'all' else [paths.get(target)]
    targets = [t for t in targets if t]

    try:
        require_truenas_key(cfg)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    if not permission_lock.acquire(blocking=False):
        return jsonify({'error': 'A permission repair is already running'}), 429

    results = []
    try:
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
                results.append({'path': path, 'success': False, 'error': 'Permission repair failed'})
    finally:
        permission_lock.release()

    return jsonify({'results': results})

@app.route('/api/test-connection', methods=['POST'])
@limiter.limit("20 per minute")
def test_connection():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    service = data.get('service')
    cfg = load_config()
    try:
        if service == 'sonarr':
            api_get(f"{validate_service_url(cfg['sonarr_url'], 'sonarr_url')}/api/v3/system/status", cfg['sonarr_api_key'])
        elif service == 'radarr':
            api_get(f"{validate_service_url(cfg['radarr_url'], 'radarr_url')}/api/v3/system/status", cfg['radarr_api_key'])
        elif service == 'truenas':
            truenas_api('GET', 'system/info')
        elif service == 'rclone':
            remote_name = validate_rclone_remote_name(cfg['rclone_remote'])
            r = subprocess.run([RCLONE_BIN, 'lsd', f"{remote_name}:/"],
                               capture_output=True, text=True, timeout=15)  # nosec B603
            if r.returncode != 0:
                logger.warning('rclone test failed stderr=%s', r.stderr.strip())
                return jsonify({'success': False, 'error': 'rclone test failed'})
        elif service == 'rtorrent':
            query_rtorrent(cfg)
        return jsonify({'success': True})
    except Exception as e:
        logger.warning('connection test failed service=%s error=%s', service, e)
        return jsonify({'success': False, 'error': 'Connection test failed'})

def parse_rclone_speed():
    """Return (speed_str, progress_str) by scanning the tail of the rclone torrent log."""
    try:
        if not os.path.exists(RCLONE_TORRENT_LOG):
            return None, None
        with open(RCLONE_TORRENT_LOG) as f:
            lines = f.readlines()[-30:]
        for line in reversed(lines):
            m = re.search(
                r'Transferred:.*?,\s*(\d+)%,\s*([\d.]+\s*\w+B/s)',
                line
            )
            if m:
                return m.group(2), m.group(1) + '%'
    except Exception:
        pass
    return None, None

# ── Torrent Sync API ──────────────────────────────────────────────────────────
@app.route('/api/torrent-sync/status')
@limiter.limit("30 per minute")
def torrent_sync_status():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    job = scheduler.get_job('torrent_sync')
    next_run = None
    if job and job.next_run_time:
        next_run = job.next_run_time.timestamp()
    speed, progress = (None, None)
    if torrent_sync_state['status'] == 'syncing':
        speed, progress = parse_rclone_speed()
    return jsonify({
        'status': torrent_sync_state['status'],
        'last_sync': torrent_sync_state['last_sync'],
        'last_error': torrent_sync_state['last_error'],
        'active_torrent': torrent_sync_state['active_torrent'],
        'next_sync': next_run,
        'interval': load_config().get('sync_interval', 5),
        'speed': speed,
        'progress': progress,
    })

@app.route('/api/torrent-sync/now', methods=['POST'])
@limiter.limit("10 per minute")
def torrent_sync_now():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    if torrent_sync_state['status'] == 'syncing':
        return jsonify({'error': 'Sync already running'}), 429
    t = threading.Thread(target=run_torrent_sync, daemon=True)
    t.start()
    return jsonify({'started': True})

@app.route('/api/torrent-sync/interval', methods=['POST'])
@limiter.limit("10 per minute")
def set_torrent_sync_interval():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    try:
        interval = max(1, min(60, int(data.get('interval', 5))))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid interval'}), 400
    cfg = load_config()
    cfg['sync_interval'] = interval
    save_config(cfg)
    reschedule_sync(interval)
    logger.info('torrent sync interval updated to %d min', interval)
    return jsonify({'success': True, 'interval': interval})

@app.route('/api/torrent-sync/history')
@limiter.limit("20 per minute")
def torrent_sync_history():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT torrent_name, category, synced_at, status, local_path '
                'FROM synced_torrents ORDER BY id DESC LIMIT 100'
            ).fetchall()
        return jsonify({'history': [dict(r) for r in rows]})
    except Exception as e:
        logger.exception('torrent sync history error')
        return public_error('Could not read history')

@app.route('/api/torrent-sync/log')
@limiter.limit("20 per minute")
def torrent_sync_log():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        if not os.path.exists(RCLONE_TORRENT_LOG):
            return jsonify({'lines': []})
        with open(RCLONE_TORRENT_LOG) as f:
            lines = f.readlines()
        return jsonify({'lines': [l.rstrip() for l in lines[-100:]]})
    except Exception:
        logger.exception('torrent sync log read error')
        return public_error('Could not read log')

init_db()
_startup_cfg = load_config()
scheduler.start()
reschedule_sync(_startup_cfg.get('sync_interval', 5))

if __name__ == '__main__':
    if ENABLE_HTTPS and not os.path.exists(CERT_PATH):
        print("Generating TLS certificate...")
        os.makedirs(BASE_DIR, exist_ok=True)
        subprocess.run([
            OPENSSL_BIN,'req','-x509','-newkey','rsa:4096',
            '-keyout', KEY_PATH, '-out', CERT_PATH,
            '-days','3650','-nodes','-subj','/CN=staging-manager'
        ], check=True)  # nosec B603
        os.chmod(KEY_PATH, 0o600)
        print(f"✓ Certificate saved")

    scheme = 'https' if ENABLE_HTTPS else 'http'
    print(f"\nStarting Media Manager on {scheme}://{APP_HOST}:{APP_PORT}\n")
    if ENABLE_HTTPS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_PATH, KEY_PATH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        app.run(host=APP_HOST, port=APP_PORT, ssl_context=ctx, debug=False)
    else:
        app.run(host=APP_HOST, port=APP_PORT, debug=False)

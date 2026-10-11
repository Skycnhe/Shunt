# ---------------------------------------------------------------- 认证：PBKDF2 密码 + 随机会话
PW_ITER = 60000  # 低端 ARM 上约 0.3 秒，只在登录 / 改密时计算
SESS_FILE = os.path.join(PANEL_DIR, "sessions.json")
SESS_TTL = 30 * 86400  # 会话 30 天无访问即过期（每次访问顺延）
SESS_MAX = 50
SESS, SESS_LOCK, TICKETS = {}, threading.Lock(), {}


def pw_hash(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PW_ITER).hex()
    return f"pbkdf2_sha256${PW_ITER}${salt}${h}"


def pw_check(pw, d):
    st = d.get("pw_hash") or ""
    if not st:
        return hmac.compare_digest(pw.encode(), (d.get("password") or "admin").encode())
    try:
        _, it, salt, h = st.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex(), h)
    except Exception:
        return False


def _tk(tok):
    return hashlib.sha256(str(tok).encode()).hexdigest()


def sess_load():
    try:
        with open(SESS_FILE) as f:
            SESS.update({k: v for k, v in json.load(f).items() if isinstance(v, dict) and v.get("exp", 0) > time.time()})
    except Exception:
        pass


def sess_save():
    try:
        tmp = SESS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(SESS, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SESS_FILE)
    except Exception as e:
        print("session save error", e, flush=True)


def sess_new(ip="", ua=""):
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with SESS_LOCK:
        for k in [k for k, v in SESS.items() if v.get("exp", 0) <= now]:
            SESS.pop(k)
        while len(SESS) >= SESS_MAX:  # 只保留最近的会话
            SESS.pop(min(SESS, key=lambda k: SESS[k].get("seen", 0)))
        SESS[_tk(tok)] = {"t": int(now), "seen": int(now), "exp": int(now + SESS_TTL), "ip": ip, "ua": ua[:120]}
        sess_save()
    return tok


def sess_ok(tok):
    if not tok:
        return False
    k, now = _tk(tok), time.time()
    with SESS_LOCK:
        e = SESS.get(k)
        if not e or e.get("exp", 0) <= now:
            SESS.pop(k, None)
            return False
        if now - e.get("seen", 0) > 3600:  # 每小时最多落盘一次，避免频繁写闪存
            e["seen"], e["exp"] = int(now), int(now + SESS_TTL)
            sess_save()
    return True


def sess_drop(tok=None, keep=None):
    """tok：注销该会话；tok 为空：注销全部（keep 除外）"""
    with SESS_LOCK:
        if tok:
            SESS.pop(_tk(tok), None)
        else:
            kk = _tk(keep) if keep else None
            for k in [k for k in SESS if k != kk]:
                SESS.pop(k)
        sess_save()


def ticket_new():
    """日志流（EventSource 无法带请求头）用的一次性票据，60 秒有效"""
    now = time.time()
    for k in [k for k, v in TICKETS.items() if v <= now]:
        TICKETS.pop(k, None)
    t = secrets.token_urlsafe(18)
    TICKETS[t] = now + 60
    return t


def ticket_use(t):
    exp = TICKETS.pop(str(t or ""), 0)
    return exp > time.time()



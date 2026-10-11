"""静态资源：gzip + ETag"""
import base64, gzip, hashlib, os, re

from .base import BASE
STATIC = {}
STATIC_TYPES = {"index.html": "text/html", "icon.svg": "image/svg+xml", "icon-180.png": "image/png", "icon-512.png": "image/png"}
MANIFEST = {"name": "Shunt 分流", "short_name": "Shunt", "description": "mihomo 旁路由面板", "start_url": "/", "scope": "/",
            "display": "standalone", "background_color": "#f2f2f7", "theme_color": "#0a84ff",
            "icons": [{"src": "/icon-180.png", "sizes": "180x180", "type": "image/png"},
                      {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}]}


def static_file(name):
    """返回 (原始, gzip, etag, 类型)；按文件修改时间缓存。图标文件缺失时（旧版面板在线更新上来）从 index.html 内嵌的图标取"""
    path = os.path.join(BASE, name)
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        if not name.endswith(".png"):
            return None
        idx = static_file("index.html")
        m = re.search(rb'rel="apple-touch-icon" href="data:image/png;base64,([A-Za-z0-9+/=]+)"', idx[0]) if idx else None
        if not m:
            return None
        raw = base64.b64decode(m.group(1))
        return raw, None, '"i%s"' % hashlib.md5(raw).hexdigest()[:16], "image/png"
    c = STATIC.get(name)
    if c and c[0] == key:
        return c[1]
    with open(path, "rb") as f:
        raw = f.read()
    gz = gzip.compress(raw, 6) if not name.endswith(".png") else None
    val = (raw, gz, '"%s"' % hashlib.md5(raw).hexdigest()[:16], STATIC_TYPES.get(name, "application/octet-stream"))
    STATIC[name] = (key, val)
    return val

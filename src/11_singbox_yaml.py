# ---- 极简 YAML 读取（只为解析 Clash 订阅里的 proxies 列表；面板保持零依赖）
def _y_strip_comment(s):
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q and (q == "'" or s[i - 1] != "\\"):
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def _y_scalar(s):
    s = s.strip()
    if not s:
        return None
    if s[0] == '"' and s.endswith('"') and len(s) > 1:
        try:
            return json.loads(s)
        except Exception:
            return s[1:-1]
    if s[0] == "'" and s.endswith("'") and len(s) > 1:
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", s) and not (len(s.lstrip("+-")) > 1 and s.lstrip("+-")[0] == "0"):
        return int(s)
    if re.fullmatch(r"[-+]?\d+\.\d+", s):
        return float(s)
    return s


def _y_flow(s, i=0):
    """解析 {..} / [..] 流式集合，返回 (值, 结束位置)"""
    def ws(i):
        while i < len(s) and s[i] in " \t\r\n":
            i += 1
        return i

    def scalar(i, stops):
        i = ws(i)
        if i < len(s) and s[i] in "'\"":
            q = s[i]
            j = i + 1
            while j < len(s):
                if s[j] == q:
                    if q == "'" and j + 1 < len(s) and s[j + 1] == "'":
                        j += 2
                        continue
                    if q == '"' and s[j - 1] == "\\":
                        j += 1
                        continue
                    break
                j += 1
            return _y_scalar(s[i:j + 1]), j + 1
        j = i
        while j < len(s) and s[j] not in stops:
            if s[j] == ":" and "}" in stops and (j + 1 >= len(s) or s[j + 1] in " ,}"):
                break
            j += 1
        return _y_scalar(s[i:j]), j

    def value(i, stops):
        i = ws(i)
        if i < len(s) and s[i] in "{[":
            return _y_flow(s, i)
        return scalar(i, stops)

    i = ws(i)
    if s[i] == "{":
        out, i = {}, i + 1
        while True:
            i = ws(i)
            if i >= len(s):
                raise ValueError("YAML 花括号未闭合")
            if s[i] == "}":
                return out, i + 1
            k, i = scalar(i, ",}")
            i = ws(i)
            v = None
            if i < len(s) and s[i] == ":":
                v, i = value(i + 1, ",}")
            out[str(k)] = v
            i = ws(i)
            if i < len(s) and s[i] == ",":
                i += 1
    if s[i] == "[":
        out, i = [], i + 1
        while True:
            i = ws(i)
            if i >= len(s):
                raise ValueError("YAML 方括号未闭合")
            if s[i] == "]":
                return out, i + 1
            v, i = value(i, ",]")
            out.append(v)
            i = ws(i)
            if i < len(s) and s[i] == ",":
                i += 1
    return scalar(i, "")


def yaml_lite(text):
    """块状 / 流式映射与列表、引号字符串、注释；不支持锚点等高级语法"""
    raw = []
    for line in text.replace("\t", "  ").splitlines():
        if line.strip() in ("---", "...") or not line.strip() or line.lstrip().startswith("#"):
            continue
        raw.append(line)
    lines, buf = [], ""
    for line in raw:  # 跨行的流式集合合并成一行
        buf = buf + " " + line.strip() if buf else line
        c = _y_strip_comment(buf)
        depth = sum(1 for ch in c if ch in "{[") - sum(1 for ch in c if ch in "}]")
        if depth <= 0:
            lines.append((len(c) - len(c.lstrip(" ")), c.strip()))
            buf = ""
    if buf:
        c = _y_strip_comment(buf)
        lines.append((len(c) - len(c.lstrip(" ")), c.strip()))

    def split_kv(t):
        if t[:1] in "'\"":
            q = t[0]
            j = t.find(q, 1)
            while q == '"' and j > 0 and t[j - 1] == "\\":
                j = t.find(q, j + 1)
            if j > 0 and t[j + 1:j + 2] == ":":
                return _y_scalar(t[:j + 1]), t[j + 2:].strip()
            return None
        m = re.match(r"^([^:{}\[\],]+?)\s*:(?:\s+(.*)|$)", t)
        return (m.group(1).strip(), (m.group(2) or "").strip()) if m else None

    def inline(v):
        if v.startswith(("{", "[")):
            return _y_flow(v)[0]
        if v in ("|", ">", "|-", ">-"):
            return ""
        return _y_scalar(v)

    def block(i, ind):
        if i >= len(lines):
            return None, i
        if lines[i][1].startswith("- ") or lines[i][1] == "-":
            out = []
            while i < len(lines) and lines[i][0] == ind and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
                rest = lines[i][1][1:].strip()
                if not rest:
                    if i + 1 < len(lines) and lines[i + 1][0] > ind:
                        v, i = block(i + 1, lines[i + 1][0])
                    else:
                        v, i = None, i + 1
                    out.append(v)
                    continue
                kv = None if rest.startswith(("{", "[")) else split_kv(rest)
                if kv is None:
                    out.append(inline(rest))
                    i += 1
                    continue
                sub = ind + len(lines[i][1]) - len(rest)
                lines[i] = (sub, rest)  # 「- key: v」等价于下一级映射的第一行
                v, i = block(i, sub)
                out.append(v)
            return out, i
        out = {}
        while i < len(lines) and lines[i][0] == ind and not lines[i][1].startswith("- "):
            kv = split_kv(lines[i][1])
            if kv is None:
                i += 1
                continue
            k, v = kv
            i += 1
            if v and v not in ("|", ">", "|-", ">-"):
                out[str(k)] = inline(v)
            elif i < len(lines) and (lines[i][0] > ind or (lines[i][0] == ind and lines[i][1].startswith("- "))):
                if v in ("|", ">", "|-", ">-"):
                    parts = []
                    while i < len(lines) and lines[i][0] > ind:
                        parts.append(lines[i][1])
                        i += 1
                    out[str(k)] = ("\n" if v.startswith("|") else " ").join(parts)
                else:
                    out[str(k)], i = block(i, lines[i][0])
            else:
                out[str(k)] = None
        return out, i

    if not lines:
        return None
    return block(0, lines[0][0])[0]



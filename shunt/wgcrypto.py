"""WireGuard 用到的密码学（纯 Python，零依赖）：X25519、ChaCha20-Poly1305、BLAKE2s，
用于注册 WARP 账户时生成密钥对，以及优选 IP 时构造握手包（Noise_IKpsk2）探测 Endpoint 是否可用、延迟多少。
只处理几十字节的握手数据，纯 Python 足够快（一次握手包约 5 ms）。"""
import base64, hashlib, hmac, os, struct, time

P = 2**255 - 19
_A24 = 121665


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(k, u):
    """RFC 7748 Montgomery ladder；k、u 均为 32 字节，返回 32 字节"""
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    k = _clamp(k)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + _A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


_BASE = (9).to_bytes(32, "little")


def keypair():
    """返回 (私钥, 公钥) 32 字节；私钥已按 RFC 7748 截断，与 wg genkey 输出等价"""
    k = bytearray(os.urandom(32))
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = bytes(k)
    return k, x25519(k, _BASE)


def pubkey(priv):
    return x25519(priv, _BASE)


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    b = base64.b64decode(str(s).strip(), validate=True)
    if len(b) != 32:
        raise ValueError("密钥长度不是 32 字节")
    return b


# ---------------- ChaCha20-Poly1305 (RFC 8439) ----------------
def _rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)


def _block(key, counter, nonce):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xffffffff for i in range(16)])


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b"\x00" * (-len(b) % 16)


def aead_encrypt(key, counter, pt, ad):
    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
    otk = _block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    mac = poly1305(otk, ad + _pad16(ad) + ct + _pad16(ct) + struct.pack("<QQ", len(ad), len(ct)))
    return ct + mac


def aead_decrypt(key, counter, ct, ad):
    """校验失败返回 None"""
    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
    otk = _block(key, 0, nonce)[:32]
    body, tag = ct[:-16], ct[-16:]
    mac = poly1305(otk, ad + _pad16(ad) + body + _pad16(body) + struct.pack("<QQ", len(ad), len(body)))
    if not hmac.compare_digest(mac, tag):
        return None
    return chacha20(key, 1, nonce, body)


# ---------------- WireGuard 握手 ----------------
def _hash(b):
    return hashlib.blake2s(b).digest()


def _hmac(k, b):
    return hmac.new(k, b, hashlib.blake2s).digest()


def _kdf(c, inp, n):
    t0 = _hmac(c, inp)
    t1 = _hmac(t0, b"\x01")
    if n == 1:
        return (t1,)
    t2 = _hmac(t0, t1 + b"\x02")
    return t1, t2


_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
_C0 = _hash(_CONSTRUCTION)
_H0 = _hash(_C0 + _IDENTIFIER)
_LAST_TS = [0]


def tai64n():
    """WireGuard 时间戳；同一个 peer 的时间戳必须单调递增，否则对端当作重放丢弃"""
    ns = max(time.time_ns(), _LAST_TS[0] + 1)
    _LAST_TS[0] = ns
    return struct.pack(">QI", 0x400000000000000a + ns // 10**9, ns % 10**9)


class Initiator:
    """预先算好与固定 peer 相关的部分（静态 DH），每次 packet() 只做一次临时密钥的 DH"""

    def __init__(self, priv, peer_pub, reserved=(0, 0, 0)):
        self.priv, self.peer = priv, peer_pub
        self.pub = pubkey(priv)
        self.ss = x25519(priv, peer_pub)
        self.h1 = _hash(_H0 + peer_pub)
        self.mac1key = _hash(b"mac1----" + peer_pub)
        self.reserved = bytes(reserved[:3]) + b"\x00" * (3 - len(reserved[:3]))

    def packet(self, fresh=False):
        """返回 (148 字节握手发起包, 发送方索引)。
        默认复用同一个临时密钥：与 peer 相关的 DH 和静态公钥密文都不变，每个包只重算时间戳密文和 mac1（约 0.2 ms），
        时间戳照样单调递增，对端正常应答；fresh=True 每次换新临时密钥"""
        if fresh or not hasattr(self, "_pre"):
            e_priv, e_pub = keypair()
            c = _kdf(_C0, e_pub, 1)[0]
            h = _hash(self.h1 + e_pub)
            c, k = _kdf(c, x25519(e_priv, self.peer), 2)
            st = aead_encrypt(k, 0, self.pub, h)
            h = _hash(h + st)
            c, k = _kdf(c, self.ss, 2)
            self._pre = (e_pub + st, k, h)
        body, k, h = self._pre
        idx = os.urandom(4)
        ts = aead_encrypt(k, 0, tai64n(), h)
        msg = b"\x01" + self.reserved + idx + body + ts
        mac1 = hashlib.blake2s(msg, digest_size=16, key=self.mac1key).digest()
        return msg + mac1 + b"\x00" * 16, idx


def is_reply(data, idx):
    """握手应答（type 2，92 字节）或 Cookie 应答（type 3，64 字节，对端繁忙）且接收方索引是我们发的"""
    if len(data) == 92 and data[0] == 2:
        return data[8:12] == idx
    if len(data) == 64 and data[0] == 3:
        return data[4:8] == idx
    return False

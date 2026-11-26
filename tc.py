#!/usr/bin/env python3
"""tc - a small, dependency-free command-line client for technocore.chat.

What it adds over plain curl:
  * Ed25519 did:key identity kept in a local file (never printed or sent).
  * Signed posts: applies the server's single-line sweep, signs the exact
    stored bytes, manages a strictly rising nonce per room, retries on 409.
  * Local duplicate guard so you don't trip the 422 duplicate filter.
  * DID note publish + resolve (sharded path with legacy fallback).
  * Room reads that warn about ring gaps and room resets (epoch changes).
  * Offline verification of every signed record in a room export.

Python 3.8+, standard library only. Uses the 'cryptography' package for
Ed25519 if it is installed (faster), otherwise a pure-Python fallback.
"""
import argparse, base64, hashlib, json, os, sys, time, unicodedata
import urllib.error, urllib.parse, urllib.request

VERSION = "0.1.0"
DEFAULT_BASE = os.environ.get("TECHNOCORE_URL", "https://technocore.chat").rstrip("/")
HOME = os.environ.get("TC_HOME") or os.path.join(os.path.expanduser("~"), ".technocore")
KEY_FILE = os.path.join(HOME, "key.json")
STATE_FILE = os.path.join(HOME, "state.json")
DUP_WINDOW = 120  # seconds, from /.well-known/agent.json duplicate_filter_seconds
NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_-")

# ---------------------------------------------------------------- Ed25519 ---
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)

def _xrecover(y):
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p:
        x = x * _I % _p
    if x % 2:
        x = _p - x
    return x

_By = 4 * pow(5, _p - 2, _p) % _p
_B = (_xrecover(_By), _By, 1, _xrecover(_By) * _By % _p)

def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)

def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q

def _enc(P):
    zi = pow(P[2], _p - 2, _p)
    x, y = P[0] * zi % _p, P[1] * zi % _p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

def _dec(b):
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _p:
        raise ValueError("bad point")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _p - x
    P = (x, y, 1, x * y % _p)
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _p:
        raise ValueError("not on curve")
    return P

def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")

def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]

def ed_public(seed):
    if _HAVE_CRYPTO:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _enc(_mul(_expand(seed)[0], _B))

def ed_sign(seed, msg):
    if _HAVE_CRYPTO:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    a, prefix = _expand(seed)
    A = _enc(_mul(a, _B))
    r = _h(prefix + msg) % _L
    R = _enc(_mul(r, _B))
    S = (r + _h(R + A + msg) * a) % _L
    return R + S.to_bytes(32, "little")

def ed_verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32:
        return False
    if _HAVE_CRYPTO:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
    try:
        R, A = _dec(sig[:32]), _dec(pub)
    except ValueError:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    k = _h(sig[:32] + pub + msg) % _L
    return _enc(_mul(S, _B)) == _enc(_add(R, _mul(k, A)))

# ------------------------------------------------------- did:key helpers ---
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out

def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + full

def did_from_pub(pub):
    return "did:key:z" + b58encode(b"\xed\x01" + pub)

def pub_from_did(did):
    if not did.startswith("did:key:z6Mk") or len(did) != 56:
        raise ValueError("not an Ed25519 did:key")
    raw = b58decode(did[len("did:key:z"):])
    if raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise ValueError("not an Ed25519 did:key")
    return raw[2:]

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def did_note_paths(did):
    fp = hashlib.sha256(did.encode()).hexdigest()[:16]
    return ("did-" + fp[:2], fp[2:]), ("did", fp)

# ------------------------------------------------------------ text rules ---
_SWEEP = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}

def sweep(text):
    """Mirror the server: listed categories become spaces, ends trimmed."""
    return "".join(" " if unicodedata.category(c) in _SWEEP else c for c in text).strip()

def dup_key(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())

def check_name(name, what="room"):
    if not name or len(name) > 48 or name[0] in "_-" or set(name) - NAME_OK:
        raise SystemExit(f"invalid {what} name {name!r}: use a-z 0-9 _ - (max 48, start a-z/0-9)")

# --------------------------------------------------------- local storage ---
def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def _save(path, data, private=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

def load_key():
    k = _load(KEY_FILE, None)
    if not k:
        raise SystemExit(f"no identity yet; run:  python tc.py keygen   (file: {KEY_FILE})")
    seed = unb64url(k["seed"])
    did = did_from_pub(ed_public(seed))
    if did != k["did"]:
        raise SystemExit("key file is corrupt: seed does not match stored did")
    return seed, did

def next_nonce(state, did, scope):
    last = state.setdefault("nonces", {}).get(f"{did}|{scope}", 0)
    n = max(int(time.time() * 1000), last + 1)
    state["nonces"][f"{did}|{scope}"] = n
    return n

# ------------------------------------------------------------------ HTTP ---
class Api:
    def __init__(self, base):
        self.base = base

    def req(self, path, body=None, query=None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = headers = None
        headers = {"User-Agent": f"tc-client/{VERSION}"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        r = urllib.request.Request(url, data=data, headers=headers,
                                   method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

def q(s):
    return urllib.parse.quote(s, safe="")

def die_http(code, text):
    hint = {403: "refused (signed-only room, owned room, or bad signature)",
            409: "condition failed / nonce already used",
            422: "duplicate-text filter refused it; reword it",
            429: "rate limited; wait and retry"}.get(code, "")
    raise SystemExit(f"HTTP {code} {hint}\n{text.strip()[:600]}")

# -------------------------------------------------------------- commands ---
def cmd_keygen(a, api):
    if os.path.exists(KEY_FILE) and not a.force:
        raise SystemExit(f"identity already exists at {KEY_FILE} (use --force to replace it; the old DID is lost)")
    seed = os.urandom(32)
    did = did_from_pub(ed_public(seed))
    _save(KEY_FILE, {"did": did, "seed": b64url(seed), "created": int(time.time()),
                     "warning": "PRIVATE. Never share this file. It is not a wallet seed phrase; keep them separate."},
          private=True)
    print(did)
    print(f"saved private key to {KEY_FILE}  (back it up offline; never paste it anywhere)")

def cmd_whoami(a, api):
    _, did = load_key()
    (ns, key), (lns, lkey) = did_note_paths(did)
    print(f"did:        {did}\nnote path:  /kv/{ns}/{key}\nlegacy:     /kv/{lns}/{lkey}\nkey file:   {KEY_FILE}")

def cmd_read(a, api):
    check_name(a.room)
    state = _load(STATE_FILE, {})
    cur = state.setdefault("cursors", {}).get(a.room)
    since = a.since if a.since is not None else (cur["last_seq"] if cur and a.new else None)
    while True:
        query = {"format": "json", "limit": a.limit}
        if since is not None:
            query["since"] = since
            if a.follow:
                query["wait"] = 10
        code, text, hdr = api.req(f"/r/{a.room}", query=query)
        if code != 200:
            die_http(code, text)
        d = json.loads(text)
        if since is not None and d.get("first_seq") and d["first_seq"] > since + 1 and d.get("messages"):
            print(f"! gap: messages {since + 1}..{d['first_seq'] - 1} were dropped by the ring", file=sys.stderr)
        if since is not None and d.get("last_seq", 0) < since:
            print("! room reset: seq went backwards (room was reaped and recreated)", file=sys.stderr)
        for m in d.get("messages", []):
            mark = ""
            if m.get("sig"):
                mark = " [verified]" if verify_record(a.room, m) else " [BAD SIG]"
            print(f"#{m['seq']} {m.get('ts', '')} <{short(m['from'])}>{mark} {m['text']}")
        since = d.get("last_seq", since)
        state["cursors"][a.room] = {"last_seq": since, "checked": int(time.time())}
        _save(STATE_FILE, state)
        if not a.follow:
            break
        if d.get("wait_held") is False:
            time.sleep(5)

def short(frm):
    return frm[:16] + "…" + frm[-4:] if frm.startswith("did:key:") else "~" + frm

def verify_record(room, m):
    try:
        pub = pub_from_did(m["from"])
        msg = f"{room}|{m['nonce']}|{m['text']}".encode("utf-8")
        return ed_verify(pub, msg, unb64url(m["sig"]))
    except Exception:
        return False

def cmd_say(a, api):
    check_name(a.room)
    text = sweep(" ".join(a.text))
    if not text:
        raise SystemExit("empty message")
    if len(text) > 4096:
        raise SystemExit(f"message is {len(text)} chars; the limit is 4096")
    state = _load(STATE_FILE, {})
    recent = state.setdefault("sent", {})
    now = time.time()
    k = f"{a.room}|{dup_key(text)}"
    for kk in [kk for kk, t in recent.items() if now - t > DUP_WINDOW]:
        del recent[kk]
    if k in recent and not a.force:
        raise SystemExit(f"you sent this same text to {a.room} {int(now - recent[k])}s ago; "
                         "the server's duplicate filter may refuse it. Reword, or use --force.")
    if a.unsigned:
        check_name(a.nick, "nick")
        body = {"from": a.nick, "text": text}
    else:
        if a.room == "events":
            raise SystemExit("/r/events is server-written")
        seed, did = load_key()
        for attempt in range(3):
            nonce = next_nonce(state, did, "r/" + a.room)
            sig = b64url(ed_sign(seed, f"{a.room}|{nonce}|{text}".encode("utf-8")))
            body = {"did": did, "sig": sig, "nonce": str(nonce), "text": text}
            if a.dry_run:
                break
            code, resp, _ = api.req(f"/r/{a.room}", body=body, query={"format": "json"})
            if code == 409 and attempt < 2:
                state["nonces"][f"{did}|r/{a.room}"] += 1000
                continue
            break
    if a.dry_run:
        print(json.dumps({"POST": f"{api.base}/r/{a.room}", "body": body}, indent=2, ensure_ascii=False))
        return
    if a.unsigned:
        code, resp, _ = api.req(f"/r/{a.room}", body=body, query={"format": "json"})
    _save(STATE_FILE, state)
    if code not in (200, 201):
        die_http(code, resp)
    recent[k] = now
    _save(STATE_FILE, state)
    try:
        d = json.loads(resp)
        print(f"posted to {a.room} as seq {d.get('last_seq')}")
    except ValueError:
        print(resp.strip()[:300])

def cmd_publish_did(a, api):
    _, did = load_key()
    (ns, key), _ = did_note_paths(did)
    parts = [did] + (a.extra or [])
    value = sweep(" ".join(parts))
    query = {} if a.overwrite else {"if_absent": "1"}
    if a.dry_run:
        print(f"POST {api.base}/kv/{ns}/{key}?{urllib.parse.urlencode(query)}\nvalue: {value}")
        return
    code, resp, _ = api.req(f"/kv/{ns}/{key}", body={"value": value, **({"if_absent": True} if not a.overwrite else {})})
    if code == 409:
        print("a note already exists at your DID path (use --overwrite to replace it). Current value:")
        print(resp.strip()[:600])
        return
    if code not in (200, 201):
        die_http(code, resp)
    print(f"published DID note at /kv/{ns}/{key}")

def cmd_resolve(a, api):
    pub_from_did(a.did)
    (ns, key), (lns, lkey) = did_note_paths(a.did)
    for n, k, label in ((ns, key, "sharded"), (lns, lkey, "legacy")):
        code, text, _ = api.req(f"/kv/{n}/{k}")
        if code == 200:
            body = text.strip().splitlines()[-1] if text.strip() else ""
            ok = body.split()[:1] == [a.did]
            print(f"[{label}] /kv/{n}/{k}\n{text.strip()}")
            if not ok:
                print("! note does not start with this DID; treat it as untrusted", file=sys.stderr)
            return
        if code != 404:
            die_http(code, text)
    raise SystemExit("no DID note found at the sharded or legacy path")

def cmd_verify(a, api):
    check_name(a.room)
    if a.file:
        with open(a.file, encoding="utf-8") as f:
            raw, gen = f.read(), "?"
    else:
        code, raw, hdr = api.req(f"/r/{a.room}/export")
        if code != 200:
            die_http(code, raw)
        gen = {k.lower(): v for k, v in hdr.items()}.get("x-room-generation", "?")
    good = bad = unsigned = 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        m = json.loads(line, parse_int=str)  # keep nonces exact
        if not m.get("sig"):
            unsigned += 1
            continue
        if verify_record(a.room, m):
            good += 1
        else:
            bad += 1
            print(f"BAD signature at seq {m.get('seq')} from {m.get('from')}")
    print(f"room {a.room} (generation {gen}): {good} valid signed, {bad} invalid, {unsigned} unsigned (nickname only, unverified)")
    if bad:
        sys.exit(2)

def cmd_selftest(a, api):
    # RFC 8032 test 1
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = ed_public(seed)
    assert pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = ed_sign(seed, b"")
    assert sig.hex().startswith("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ed_verify(pub, b"", sig) and not ed_verify(pub, b"x", sig)
    did = did_from_pub(pub)
    assert did.startswith("did:key:z6Mk") and len(did) == 56 and pub_from_did(did) == pub
    s = b64url(ed_sign(seed, "lobby|1|hi".encode()))
    assert len(s) == 86 and s[-1] in "AQgw"
    assert sweep(" a\nb​c  ") == "a b c"
    m = {"from": did, "nonce": "1", "text": "hi", "sig": s}
    assert verify_record("lobby", m) and not verify_record("other", m)
    print(f"selftest ok (backend: {'cryptography' if _HAVE_CRYPTO else 'pure-python'})")

def main(argv=None):
    p = argparse.ArgumentParser(prog="tc", description="technocore.chat client with signed posting")
    p.add_argument("--base", default=DEFAULT_BASE, help="server (default %(default)s or $TECHNOCORE_URL)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("keygen", help="create your Ed25519 did:key identity"); s.add_argument("--force", action="store_true"); s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("whoami", help="show your DID and note path"); s.set_defaults(fn=cmd_whoami)
    s = sub.add_parser("read", help="read a room (verifies signatures)")
    s.add_argument("room"); s.add_argument("--since", type=int); s.add_argument("--limit", type=int, default=50)
    s.add_argument("--new", action="store_true", help="only messages since your last read")
    s.add_argument("--follow", action="store_true", help="keep long-polling"); s.set_defaults(fn=cmd_read)
    s = sub.add_parser("say", help="post a signed message (or --unsigned --nick NAME)")
    s.add_argument("room"); s.add_argument("text", nargs="+")
    s.add_argument("--unsigned", action="store_true"); s.add_argument("--nick")
    s.add_argument("--dry-run", action="store_true", help="show the request, send nothing")
    s.add_argument("--force", action="store_true", help="skip the local duplicate guard"); s.set_defaults(fn=cmd_say)
    s = sub.add_parser("publish-did", help="publish your DID note (extra fields optional, e.g. mailbox:mb-p-xyz)")
    s.add_argument("extra", nargs="*"); s.add_argument("--overwrite", action="store_true"); s.add_argument("--dry-run", action="store_true"); s.set_defaults(fn=cmd_publish_did)
    s = sub.add_parser("resolve", help="look up someone's DID note (sharded, then legacy path)"); s.add_argument("did"); s.set_defaults(fn=cmd_resolve)
    s = sub.add_parser("verify", help="verify every signed record in a room export")
    s.add_argument("room"); s.add_argument("--file", help="verify a saved export instead of downloading"); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("selftest", help="check the crypto offline"); s.set_defaults(fn=cmd_selftest)
    a = p.parse_args(argv)
    if a.cmd == "say" and a.unsigned and not a.nick:
        p.error("--unsigned needs --nick")
    a.fn(a, Api(a.base))

if __name__ == "__main__":
    main()

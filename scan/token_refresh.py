"""
Keep ZAP's injected auth token fresh during a long authenticated scan.

Problem: scan/auth_scan.py injects a STATIC bearer token. On a long active scan a JWT expires,
ZAP keeps sending the stale token, and it ends up scanning the login wall instead of the app.

Design (redo the same login step on a timer, then replace the auth header):
The browser-use login already made the real login request THROUGH the ZAP proxy, so ZAP has it
in history. We capture that one request once, then REPLAY it on an interval to mint a fresh
token and rewrite ZAP's Authorization/Cookie Replacer rules. Same login step, but replayed
programmatically -> no second browser and no LLM per refresh.

Run it alongside the scan (start right after login, before the scan fills history):
    python scan/token_refresh.py --zap http://127.0.0.1:8080 --every 600

Assumes a single-request, token-in-JSON login (Juice Shop and most SPAs). Multi-step / rotating-
CSRF logins need the heavier variant (re-run the browser-use agent) instead.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import httpx

RES = Path(__file__).parent.parent / "resources"   # repo-root/resources


def make_zap(base):
    c = httpx.Client(timeout=30)
    def zap(path, **params):
        r = c.get(f"{base}{path}", params=params)
        r.raise_for_status()
        return r.json()
    return zap


def read_token():
    st = json.loads((RES / "storage_state.json").read_text())
    for o in st.get("origins", []):
        for i in o.get("localStorage", []):
            if i["name"] == "token":
                return i["value"]
    for ck in st.get("cookies", []):
        if ck["name"] == "token":
            return ck["value"]
    sys.exit("no token in resources/storage_state.json — run the browser-use login first")


def set_auth_token(zap, token):
    """Rewrite the two Replacer rules so ZAP attaches the fresh token to every request."""
    for desc in ("bu-auth-hdr", "bu-auth-cookie"):
        try:
            zap("/JSON/replacer/action/removeRule/", description=desc)
        except httpx.HTTPError:
            pass  # not present yet on first set
    zap("/JSON/replacer/action/addRule/", description="bu-auth-hdr", enabled="true",
        matchType="REQ_HEADER", matchString="Authorization", matchRegex="false",
        replacement=f"Bearer {token}")
    zap("/JSON/replacer/action/addRule/", description="bu-auth-cookie", enabled="true",
        matchType="REQ_HEADER", matchString="Cookie", matchRegex="false",
        replacement=f"token={token}")


def find_path(obj, target, path=()):
    """Where does `target` sit in a nested JSON object? Returns a list of keys/indices, or None."""
    if obj == target:
        return list(path)
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = find_path(v, target, path + (k,))
            if p is not None:
                return p
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            p = find_path(v, target, path + (i,))
            if p is not None:
                return p
    return None


def get_path(obj, path):
    for k in path:
        obj = obj[k]
    return obj


def _headers(raw):
    return dict((h.split(":", 1)[0].strip().lower(), h.split(":", 1)[1].strip())
                for h in raw.split("\r\n")[1:] if ":" in h)


def capture_login(zap, token):
    """The login request = the one in ZAP history whose RESPONSE body contains the token."""
    msgs = zap("/JSON/core/view/messages/").get("messages", [])
    for m in reversed(msgs):                       # newest first
        body = m.get("responseBody") or ""
        if not token or token not in body:
            continue
        raw = m.get("requestHeader", "")
        line = raw.split("\r\n", 1)[0].split()
        if len(line) < 2:
            continue
        method, path = line[0], line[1]
        h = _headers(raw)
        url = path if path.startswith("http") else f"https://{h.get('host', '')}{path}"
        try:
            tok_path = find_path(json.loads(body), token)
        except Exception:
            tok_path = None
        return {"method": method, "url": url,
                "ct": h.get("content-type", "application/json"),
                "body": m.get("requestBody", ""), "token_path": tok_path}
    return None


def replay_login(login):
    r = httpx.request(login["method"], login["url"], content=login["body"],
                      headers={"Content-Type": login["ct"]}, verify=False, timeout=30)
    r.raise_for_status()
    if login["token_path"] is None:
        raise RuntimeError("token path unknown; cannot read refreshed token")
    return get_path(r.json(), login["token_path"])


def main():
    ap = argparse.ArgumentParser(description="refresh ZAP's injected auth token on an interval")
    ap.add_argument("--zap", default="http://127.0.0.1:8080")
    ap.add_argument("--every", type=int, default=600, help="seconds between refreshes (< token TTL)")
    a = ap.parse_args()
    zap = make_zap(a.zap)

    token = read_token()
    set_auth_token(zap, token)
    login = capture_login(zap, token)
    if not login:
        sys.exit("could not find the login request in ZAP history — run the browser-use login "
                 "THROUGH the ZAP proxy first, then start this before the scan fills history")
    print(f"[refresh] captured login: {login['method']} {login['url']}  (every {a.every}s)")

    while True:
        time.sleep(a.every)
        try:
            token = replay_login(login)
            set_auth_token(zap, token)
            print(f"[refresh] token rotated at {time.strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"[refresh] failed ({type(e).__name__}: {e}) — keeping previous token")


def _selfcheck():
    d = {"status": "ok", "authentication": {"umail": "x", "token": "T0"}}
    p = find_path(d, "T0")
    assert p == ["authentication", "token"], p
    assert get_path(d, p) == "T0"
    raw = "POST /rest/user/login HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/json\r\n"
    assert _headers(raw)["host"] == "app.example"
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        main()

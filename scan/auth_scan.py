"""
Combine browser-use output with ZAP for an AUTHENTICATED scan, matching the SCAN CONFIG of
the production runner.js: beta rule packs installed (pscanrulesBeta + ascanrulesBeta, ~112
-> 140 rules), a fresh 'az-auth' policy with every rule at HIGH attack strength / HIGH alert
threshold, destructive rules disabled, and all passive rules on. This is applied here via the
ZAP API (install_beta / set_scan_options / configure_policy) so one script holds the whole
config -- no startup flags or .prop needed for the active policy. Env vars ATTACK_STRENGTH /
ALERT_THRESHOLD / ASCAN_MAX_MINS / ASCAN_MAX_RULE_MINS / ZAP_THREADS override, same as runner.js.

Sequence: (optional token inject) -> spider -> passive drain -> ajax spider -> active scan.
For the crawl A/B we run --no-inject --skip-spider --skip-ajax so the active scan hits only the
surface the proxied browser captured. --disable-scanners adds local memory-savers (e.g. 40026
DOM-XSS OOMs a small ZAP); --no-beta skips the add-on install.

Assumes a ZAP daemon (proxy+API, no key) at ZAP_BASE with marketplace/internet for the beta install.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).parent
RES = HERE.parent / "resources"   # repo-root/resources (this file lives in scan/)
ZAP = os.getenv("ZAP_BASE", "http://127.0.0.1:8080")
TARGET = os.getenv("TARGET_URL", "https://webapp3.wimify.xyz").rstrip("/")  # overridden by --url
INJECT = True                       # --no-inject: skip token injection (production-faithful; auth comes from proxied browser traffic)
SKIP_AJAX = False                   # --skip-ajax: skip the ajax spider phase
SKIP_SPIDER = False                 # --skip-spider: active-scan only the tree already captured (e.g. from the proxied browser)
NO_ASCAN = False                    # --no-ascan: passive scan only (no active scan) — fits in low-memory ZAP
DISABLE_SCANNERS = ""               # --disable-scanners: comma ids to drop from the active policy (e.g. 40026 DOM-XSS OOMs low-mem ZAP)
OUT_FILE = RES / "zap_auth_scan.json"  # --out: alerts output path

# --- scan config mirrored from runner.js (az-scanner-api auth-scan container) ---
# Everything runner.js does at ZAP startup / configureScanPolicy, applied here via the ZAP API
# so this stays the single scan script. Env vars override, same names/defaults as runner.js.
SCAN_POLICY = "az-auth"
ATTACK_STRENGTH = os.getenv("ATTACK_STRENGTH", "HIGH")     # LOW|MEDIUM|HIGH|INSANE  (runner.js default HIGH)
ALERT_THRESHOLD = os.getenv("ALERT_THRESHOLD", "HIGH")     # LOW|MEDIUM|HIGH         (runner.js default HIGH)
DESTRUCTIVE_RULE_IDS = ["90028", "30001", "30002", "30003"]   # runner.js DESTRUCTIVE_RULE_IDS
BETA_ADDONS = ["pscanrulesBeta", "ascanrulesBeta"]        # runner.js -addoninstall (112 rules -> 140)
ASCAN_MAX_MINS = os.getenv("ASCAN_MAX_MINS", "240")       # runner.js scanner.maxScanDurationInMins
ASCAN_MAX_RULE_MINS = os.getenv("ASCAN_MAX_RULE_MINS", "10")  # runner.js scanner.maxRuleDurationInMins
ZAP_THREADS = os.getenv("ZAP_THREADS", "2")              # runner.js scanner.threadPerHost
INSTALL_BETA = True                 # --no-beta: skip beta add-on install (already present, or stable-only run)

c = httpx.Client(timeout=60)


def load_prop(path: Path) -> dict:
    cfg = {}
    if not path.exists():
        return cfg   # optional: spider/ascan params fall back to the defaults in P()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    return cfg


PROP = load_prop(HERE / "auth-scan.prop")


def P(key: str, default: str) -> str:
    return PROP.get(key, default)


def zap(path: str, **params) -> dict:
    r = c.get(f"{ZAP}{path}", params=params)
    r.raise_for_status()
    return r.json()


def get_token() -> str:
    st = json.loads((RES / "storage_state.json").read_text())
    for o in st.get("origins", []):
        for i in o.get("localStorage", []):
            if i["name"] == "token":
                return i["value"]
    for ck in st.get("cookies", []):
        if ck["name"] == "token":
            return ck["value"]
    sys.exit("No token in resources/storage_state.json — run bu_auth_proof.py first.")


def poll(view: str, label: str, timeout_secs: int, scan_id=None, done=None) -> None:
    done = done or (lambda s: str(s.get("status")) == "100")
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        try:
            st = zap(view, scanId=scan_id) if scan_id is not None else zap(view)
        except httpx.HTTPError:
            print(f"  {label}: ZAP unreachable — stopping poll")
            return
        if done(st):
            print(f"  {label}: done")
            return
        print(f"  {label}: {st.get('status')}")
        time.sleep(6)
    print(f"  {label}: timeout ({timeout_secs}s) — continuing")


def report(who: str, tag: str) -> None:
    try:
        alerts = zap("/JSON/core/view/alerts/", baseurl=TARGET, start="0", count="9999").get("alerts", [])
    except httpx.HTTPError:
        print(f"  [{tag}] could not fetch alerts (ZAP unreachable)")
        return
    by_risk: dict[str, int] = {}
    names: dict[str, str] = {}
    for a in alerts:
        by_risk[a["risk"]] = by_risk.get(a["risk"], 0) + 1
        names.setdefault(a["risk"] + "|" + a["alert"], a["url"])
    OUT_FILE.write_text(json.dumps(alerts, indent=2))
    print(f"\n===== AUTH SCAN RESULT ({tag}) =====")
    print(f"authenticated as : {who}")
    print(f"total alerts     : {len(alerts)}  ({len(names)} distinct types)")
    for risk in ("High", "Medium", "Low", "Informational"):
        if by_risk.get(risk):
            print(f"  {risk:<14}: {by_risk[risk]}")
    print("distinct findings:")
    for k in sorted(names)[:20]:
        risk, alert = k.split("|", 1)
        print(f"  [{risk}] {alert}")
    print(f"full report -> {OUT_FILE}")
    print("=================================")


def install_beta() -> None:
    # runner.js installs the beta packs at ZAP startup (-addoninstall); we do it at runtime via the
    # marketplace API so any stock ZAP works. Poll until a known beta rule (NoSQL Injection) appears.
    print(f"== beta: installing {BETA_ADDONS} (112 rules -> ~140) ==")
    try:
        zap("/JSON/autoupdate/action/updateAddons/")
    except httpx.HTTPError:
        pass
    for addon in BETA_ADDONS:
        try:
            zap("/JSON/autoupdate/action/installAddon/", id=addon)
        except httpx.HTTPError as e:
            print(f"  installAddon {addon}: {type(e).__name__}")
    for _ in range(40):  # ~2 min
        try:
            names = {s["name"] for s in zap("/JSON/ascan/view/scanners/").get("scanners", [])}
        except httpx.HTTPError:
            names = set()
        if any("NoSQL" in n for n in names):
            print(f"  beta active — {len(names)} active-scan rules loaded")
            return
        time.sleep(3)
    print("  WARNING: beta rules not confirmed after 2 min (marketplace unreachable?) — continuing")


def set_scan_options() -> None:
    # runner.js sets these as ZAP -config flags at startup; same effect via the options API.
    for path, val in (
        ("/JSON/ascan/action/setOptionMaxScanDurationInMins/", ASCAN_MAX_MINS),
        ("/JSON/ascan/action/setOptionMaxRuleDurationInMins/", ASCAN_MAX_RULE_MINS),
        ("/JSON/ascan/action/setOptionThreadPerHost/", ZAP_THREADS),
    ):
        try:
            zap(path, Integer=val)
        except httpx.HTTPError as e:
            print(f"  {path.split('/')[-2]}: {type(e).__name__}")


def configure_policy() -> None:
    # Mirror of runner.js configureScanPolicy(): fresh az-auth policy, all rules on at HIGH/HIGH,
    # destructive rules off, all passive rules on.
    print(f"== policy '{SCAN_POLICY}': strength={ATTACK_STRENGTH} threshold={ALERT_THRESHOLD} ==")
    try:
        zap("/JSON/ascan/action/removeScanPolicy/", scanPolicyName=SCAN_POLICY)
    except httpx.HTTPError:
        pass  # first run: nothing to remove
    zap("/JSON/ascan/action/addScanPolicy/", scanPolicyName=SCAN_POLICY)
    zap("/JSON/ascan/action/enableAllScanners/", scanPolicyName=SCAN_POLICY)
    for cat in zap("/JSON/ascan/view/policies/", scanPolicyName=SCAN_POLICY).get("policies", []):
        cid = cat["id"]
        zap("/JSON/ascan/action/setPolicyAttackStrength/", id=cid, attackStrength=ATTACK_STRENGTH, scanPolicyName=SCAN_POLICY)
        zap("/JSON/ascan/action/setPolicyAlertThreshold/", id=cid, alertThreshold=ALERT_THRESHOLD, scanPolicyName=SCAN_POLICY)
    # destructive rules off (runner.js) + any local memory-saver ids (e.g. 40026 DOM-XSS)
    drop = DESTRUCTIVE_RULE_IDS + [x.strip() for x in DISABLE_SCANNERS.split(",") if x.strip()]
    for rid in drop:
        try:
            zap("/JSON/ascan/action/disableScanners/", ids=rid, scanPolicyName=SCAN_POLICY)
        except httpx.HTTPError:
            print(f"  rule {rid} not present in this build")
    # verify destructive rules are actually off (runner.js verifyDestructiveRulesOff)
    still_on = [f"{s['id']} {s['name']}" for s in zap("/JSON/ascan/view/scanners/", scanPolicyName=SCAN_POLICY).get("scanners", [])
                if s["id"] in DESTRUCTIVE_RULE_IDS and s["enabled"] == "true"]
    if still_on:
        sys.exit(f"Refusing to scan: destructive rules still enabled — {', '.join(still_on)}")
    zap("/JSON/pscan/action/enableAllScanners/")


def main() -> None:
    if INJECT:
        token = get_token()
        print("== 1. inject token into ZAP (Replacer: Authorization header + token cookie) ==")
        zap("/JSON/replacer/action/addRule/", description="bu-auth-hdr", enabled="true",
            matchType="REQ_HEADER", matchString="Authorization", matchRegex="false",
            replacement=f"Bearer {token}")
        zap("/JSON/replacer/action/addRule/", description="bu-auth-cookie", enabled="true",
            matchType="REQ_HEADER", matchString="Cookie", matchRegex="false",
            replacement=f"token={token}")

        print("== 2. verify authenticated (whoami through ZAP) ==")
        who = None
        for attempt in range(5):  # target can be flaky; retry transient disconnects
            try:
                with httpx.Client(proxy=ZAP, verify=False, timeout=30) as pc:
                    r = pc.get(f"{TARGET}/rest/user/whoami")
                who = (r.json().get("user") or {}).get("email")
                print(f"  whoami http={r.status_code} email={who}")
                if who:
                    break
            except httpx.HTTPError as e:
                print(f"  whoami attempt {attempt+1} transient error: {type(e).__name__}")
            time.sleep(3)
        if not who:
            sys.exit("ZAP is not authenticated (whoami returned no user after retries). Aborting scan.")
    else:
        # Production-faithful: no token injection. Authenticated surface comes only from the
        # requests the proxied browser already made (login, and any click-around). ZAP's own
        # spider requests are unauthenticated, exactly like runner.js.
        who = "(proxied browser session; no token injection)"
        print("== 1-2. no-inject mode: scanning the surface captured from the browser session ==")

    # ---- exact auth-scan sequence from runner.js: spider -> ajax spider -> active scan ----
    if SKIP_SPIDER:
        print("== 3. spider: skipped (--skip-spider); active-scanning only the already-captured tree ==")
    else:
        print(f"== 3. spider (maxChildren={P('spider.maxChildren','10')} recurse={P('spider.recurse','true')}) ==")
        zap("/JSON/core/action/accessUrl/", url=TARGET)
        sid = zap("/JSON/spider/action/scan/", url=TARGET,
                  maxChildren=P("spider.maxChildren", "10"), recurse=P("spider.recurse", "true")).get("scan")
        poll("/JSON/spider/view/status/", "spider", int(P("spider.pollTimeoutSecs", "300")), scan_id=sid)

    print("== 4. passive scan drain (safe snapshot before active scan) ==")
    for _ in range(80):
        try:
            rem = zap("/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")
        except httpx.HTTPError:
            break
        if str(rem) == "0":
            break
        time.sleep(3)
    report(who, "passive+spider")

    if SKIP_AJAX:
        print("== 5. ajax spider: skipped (--skip-ajax) ==")
    else:
        print(f"== 5. ajax spider (browser={P('ajaxSpider.browser','firefox-headless')}) ==")
        try:
            zap("/JSON/ajaxSpider/action/scan/", url=TARGET,
                inScopeOnly=P("ajaxSpider.inScopeOnly", "false"), browser=P("ajaxSpider.browser", "firefox-headless"))
            time.sleep(5)  # let it leave the idle 'stopped' state before we poll
            poll("/JSON/ajaxSpider/view/status/", "ajaxSpider", int(P("ajaxSpider.pollTimeoutSecs", "300")),
                 done=lambda s: s.get("status") == "stopped")
        except httpx.HTTPError as e:
            print(f"  ajax spider unavailable ({type(e).__name__}) — skipping (needs Firefox in the ZAP image)")

    if NO_ASCAN:
        print("== 6. active scan: skipped (--no-ascan); passive results only ==")
    else:
        print(f"== 6. active scan (recurse={P('ascan.recurse','true')}) ==")
        if INSTALL_BETA:
            install_beta()
        set_scan_options()
        configure_policy()
        try:
            aid = zap("/JSON/ascan/action/scan/", url=TARGET, recurse=P("ascan.recurse", "true"),
                      scanPolicyName=SCAN_POLICY).get("scan")
            poll("/JSON/ascan/view/status/", "ascan", int(P("ascan.pollTimeoutSecs", "1800")), scan_id=aid)
        except httpx.HTTPError as e:
            print(f"  active scan interrupted ({type(e).__name__}) — ZAP may have run low on memory; "
                  "reporting passive + partial. (auth-scan.prop notes the throttling option.)")

    # captured-surface metric: how many distinct URLs the browser session put in ZAP's tree
    try:
        n_urls = len(set(zap("/JSON/core/view/urls/", baseurl=TARGET).get("urls", [])))
        print(f"captured URLs in ZAP tree: {n_urls}")
    except httpx.HTTPError:
        pass

    report(who, "final")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ZAP authenticated scan (token injection or production-faithful)")
    ap.add_argument("--url", default=TARGET, help="target URL to scan (must match the login target)")
    ap.add_argument("--no-inject", action="store_true",
                    help="do NOT inject the token; scan only what the proxied browser captured (production-faithful)")
    ap.add_argument("--skip-ajax", action="store_true", help="skip the ajax spider phase")
    ap.add_argument("--skip-spider", action="store_true",
                    help="skip ZAP's spider; active-scan only the already-captured tree (e.g. proxied browser traffic)")
    ap.add_argument("--no-ascan", action="store_true",
                    help="passive scan only, no active scan (fits low-memory ZAP; use for surface A/B)")
    ap.add_argument("--disable-scanners", default="",
                    help="comma-separated active-scan rule ids to disable, e.g. 40026 (DOM-XSS OOMs low-mem ZAP)")
    ap.add_argument("--no-beta", action="store_true",
                    help="skip installing the beta rule packs (use when already present or scanning stable-only)")
    ap.add_argument("--out", default=str(OUT_FILE), help="alerts output JSON path")
    args = ap.parse_args()
    TARGET = args.url.rstrip("/")
    INJECT = not args.no_inject
    SKIP_AJAX = args.skip_ajax
    SKIP_SPIDER = args.skip_spider
    NO_ASCAN = args.no_ascan
    DISABLE_SCANNERS = args.disable_scanners
    INSTALL_BETA = not args.no_beta
    OUT_FILE = Path(args.out)
    main()

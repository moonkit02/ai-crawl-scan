# ai-crawl-scan

Show how an **AI crawl** (browser-use) feeds a **ZAP authenticated active scan**, and measure it
against a human's manual crawl. The scan config is matched to the production `runner.js`
(beta rule packs, `az-auth` policy, HIGH attack strength / HIGH alert threshold, destructive
rules off), so any coverage gap is attributable to the crawl, not the scanner.

## Layout

```
run.sh                    orchestrator (entry point): start ZAP → crawl → scan, N runs
crawl/
  bu_auth_proof.py        AI crawler: browser-use logs in + crawls through the ZAP proxy
  sse_gateway_llm.py      OpenAI-compatible client for the MiniMax/SSE gateway (drives browser-use)
  crawl_agent.py          standalone form-submitting crawler variant
scan/
  auth_scan.py            ZAP scan, self-configured to match runner.js (beta, az-auth policy, HIGH/HIGH)
webui/
  serve.py                control panel: form -> browser-use login -> ZAP ajax spider + active scan
  index.html              the form (target, login page, username, password, strength)
dashboard/
  progress_server.py      serves a live scan-progress page + scrapes ZAP into progress.json
  dashboard.html          the live progress page
docker/
  Dockerfile              ZAP + browser-use + Chromium in one image (prod-shaped)
  docker-entrypoint.sh    in-container: ZAP daemon → crawl → scan
misc/                     CRAWLER_DESIGN.md, zap_compare.html (docs / legacy viewer)
resources/                run outputs (JSON + recordings); manual-163824.json baseline (git-tracked)
old-resource/             archived earlier results
```

Paths are computed relative to the repo root, so `crawl/` and `scan/` scripts still read/write
the single top-level `resources/`.

## Setup

```bash
cp .env.example .env      # fill LLM_BASE_URL / LLM_API_KEY / LLM_MODEL
uv sync                   # or: uv run will create the venv on first call
```

## Run

```bash
# 3 AI crawl+scan runs as admin, runner.js scan config:
./run.sh --url https://webapp3.wimify.xyz --user admin@juice-sh.op --pass admin123 --runs 3

# stable-only scan (skip beta packs):
./run.sh --stable
```

Outputs land in `resources/<name>_<i>.json` (ZAP alerts) and `resources/recordings/<name>_<i>.mp4`.

Live progress page (optional, while a scan runs):

```bash
uv run python dashboard/progress_server.py   # http://localhost:8090/dashboard/dashboard.html
# set RESULT_FILE=/resources/<name>_1.json so the "View result" button links to your run
```

## Control panel (form UI)

A browser form that decouples auth from scanning: browser-use only logs in, ZAP does the crawl.

```bash
uv run python webui/serve.py     # http://localhost:8095
```

Enter target URL, login-page URL, username, password (+ strength / stable toggle) and run. It
starts ZAP (beta packs) if needed, has browser-use log in and capture the token, injects it, then
runs ZAP's AJAX spider + active scan and shows live progress + a result summary. Output:
`resources/webscan.json`. Needs Docker + LLM creds in `.env`.

## Docker (single container, like prod)

`Dockerfile` packages ZAP + browser-use + Chromium in one image — the same shape as the
production `auth-scan` container, but with the live AI crawl instead of a Playwright replay.
`docker-entrypoint.sh` starts the ZAP daemon in-container, crawls through it, then scans.

```bash
docker build -f docker/Dockerfile -t ai-crawl-scan .   # build context = repo root

docker run --rm \
  -e TARGET_URL=https://webapp3.wimify.xyz \
  -e APP_USER=admin@juice-sh.op -e APP_PASS=admin123 \
  -e LLM_BASE_URL=... -e LLM_API_KEY=... -e LLM_MODEL=... \
  -m 6g \
  -v "$PWD/out:/app/resources" \
  ai-crawl-scan
```

Results land in the mounted `out/` (`crawl_scan.json` + `recordings/crawl_scan.mp4`).
Toggles: `-e STABLE=1` (skip beta packs), `-e LOGIN_ONLY=1` (log in then scan, no crawl),
`-e NAME=...`, plus the scan knobs below. Give it **≥6 GB** (`-m 6g`): ZAP + Chromium together
need the headroom (this is why it OOM'd at 4 GB earlier). LLM creds and `TARGET_URL` are passed
at runtime, never baked into the image.

## Scan-config knobs (env; defaults = runner.js)

`ATTACK_STRENGTH=HIGH` `ALERT_THRESHOLD=HIGH` `ASCAN_MAX_MINS=240` `ASCAN_MAX_RULE_MINS=10`
`ZAP_THREADS=2`. Locally, rule `40026` (DOM-XSS) is dropped by `run.sh` because it drives a
headless browser, sends 0 requests, and OOMs a small ZAP; override with `LOCAL_DISABLE=`.

Beta packs are installed at scan time via the ZAP marketplace API, so the ZAP container needs
internet. Use `--stable` / `--no-beta` to skip.

#!/usr/bin/env bash
# In-container orchestration (replaces run.sh's docker-run logic): start the ZAP daemon
# INSIDE this container, crawl through it, then active-scan. Mirrors prod runner.js, which
# also runs zap.sh + a proxied browser in one container.
#
# Config via env (see Dockerfile ENV): TARGET_URL (required), APP_USER, APP_PASS, NAME,
# ATTACK_STRENGTH, ALERT_THRESHOLD, ZAP_THREADS, LLM_BASE_URL/LLM_API_KEY/LLM_MODEL.
# Toggles: STABLE=1 (skip beta packs), LOGIN_ONLY=1 (log in then scan, no crawl).
set -uo pipefail
cd /app

ZAP=http://127.0.0.1:8080
: "${TARGET_URL:?set TARGET_URL, e.g. -e TARGET_URL=https://target}"

EXPLORE="--explore"; [ "${LOGIN_ONLY:-}" = "1" ] && EXPLORE=""
BETA_STARTUP=(); BETA_SCAN=""
if [ "${STABLE:-}" = "1" ]; then
  BETA_SCAN="--no-beta"
else
  # Install beta packs at ZAP startup so the beta PASSIVE rules are live during the crawl.
  BETA_STARTUP=(-addonupdate -addoninstall pscanrulesBeta -addoninstall ascanrulesBeta)
fi

echo "== starting ZAP daemon (in-container)${STABLE:+, stable} =="
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true "${BETA_STARTUP[@]}" &
echo -n "waiting for ZAP (beta install adds startup time)"
until curl -s "$ZAP/JSON/core/view/version/" >/dev/null 2>&1; do echo -n "."; sleep 2; done; echo " up"

echo "== AI crawl through ZAP =="
python crawl/bu_auth_proof.py --url "$TARGET_URL" --username "$APP_USER" --password "$APP_PASS" \
  --proxy "$ZAP" --headless $EXPLORE --video-name "$NAME"

echo "== active scan (runner.js config: ${ATTACK_STRENGTH:-MEDIUM}, ${BETA_SCAN:-beta}) =="
python scan/auth_scan.py --url "$TARGET_URL" --no-inject --skip-spider --skip-ajax \
  --disable-scanners "${LOCAL_DISABLE:-40026}" $BETA_SCAN --out "resources/${NAME}.json"

echo "== done -> /app/resources/${NAME}.json (+ recordings/${NAME}.mp4) =="

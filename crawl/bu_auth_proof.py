"""
browser-use, driven by your OpenAI-compatible Bedrock gateway (MiniMax), logs into a
web app and:
  - exports a Playwright-format storage_state.json (token) for ZAP,
  - records the run as agent_history.gif (per-step) and a .webm/.mp4 video.

Config comes from .env next to this file (or the shell):
    LLM_BASE_URL   your gateway URL, e.g. https://<id>.lambda-url.<region>.on.aws/v1
    LLM_API_KEY    your gateway key
    LLM_MODEL      model id, e.g. minimax.minimax-m2.5
Optional:
    TARGET_URL     default https://webapp3.wimify.xyz
    APP_EMAIL      default bu-proof@test.local
    APP_PASSWORD   default BUproof!234
    EXPLORE        set 1 to also click around read-only after login (fatter crawl)
    HEADLESS       set 1 to hide the browser window

Run:
    uv run python bu_auth_proof.py
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from browser_use import Agent, BrowserProfile, BrowserSession
from browser_use.browser.events import SaveStorageStateEvent
from browser_use.browser.profile import ProxySettings
from browser_use.llm.messages import UserMessage

from sse_gateway_llm import ChatSSEGateway

load_dotenv(Path(__file__).parent / ".env")
load_dotenv()  # also pick up shell / cwd .env

RES = Path(__file__).parent.parent / "resources"   # repo-root/resources (this file lives in crawl/)
RES.mkdir(exist_ok=True)
OUT = RES / "storage_state.json"
# CLI flags override these; these in turn default to env vars, then to the Juice Shop demo.
DEFAULT_URL = os.getenv("TARGET_URL", "https://webapp3.wimify.xyz")
DEFAULT_EMAIL = os.getenv("APP_EMAIL", "bu-proof@test.local")
DEFAULT_PASSWORD = os.getenv("APP_PASSWORD", "BUproof!234")


async def main(args: argparse.Namespace) -> None:
    target, email, password = args.url, args.email, args.password
    base_url = os.getenv("LLM_BASE_URL")
    api_key = os.getenv("LLM_API_KEY")
    model = os.getenv("LLM_MODEL")
    if not (base_url and api_key and model):
        sys.exit("Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env")
    print(f"Using model: {model}\n")

    llm = ChatSSEGateway(model=model, base_url=base_url.rstrip("/"), api_key=api_key, temperature=0.0)

    # Fail fast: confirm browser-use's call path works against the gateway before opening Chrome.
    print("Sanity-checking browser-use -> gateway call path...")
    try:
        r = await llm.ainvoke([UserMessage(content="Reply with the single word: works")])
        print(f"  gateway replied: {r.completion!r}\n")
    except Exception as e:
        sys.exit(f"browser-use could not talk to the gateway: {e}")

    rec_dir = RES / "recordings"
    rec_dir.mkdir(exist_ok=True)
    # Start LOGGED OUT: delete any prior token file so the browser does not load it at
    # startup (otherwise the agent begins already-authenticated and skips the real login).
    # storage_state=OUT still handles the reliable SAVE at session end.
    OUT.unlink(missing_ok=True)
    profile = BrowserProfile(
        headless=args.headless,
        storage_state=str(OUT),
        user_data_dir=None,
        record_video_dir=str(rec_dir),   # video of the whole session
        proxy=ProxySettings(server=args.proxy) if args.proxy else None,  # route via ZAP so it captures the session
        disable_security=bool(args.proxy),                               # ignore MITM cert when proxied
    )
    session = BrowserSession(browser_profile=profile)

    task = (
        f"Go to {target}. It is a web application; the login may be a form or behind an "
        f"Account/Login menu. Dismiss any welcome/cookie banner first. "
        f"Then log in with username/email '{email}' and password '{password}': find the login "
        f"form, type the email/username into its field, type the password into the password field, "
        f"and submit. Confirm you are logged in (the account area shows the user / a Logout option). "
    )
    # General anti-stuck rule for SPAs: many overlays/sidebars have no close button and
    # dismiss on an outside click or Escape. Without this the agent loops hunting for an X.
    task += (
        "GENERAL NAVIGATION RULE: to close any sidebar, drawer, panel, overlay, tooltip or "
        "dialog that has no visible close/X button, press the Escape key, or click an empty "
        "neutral area of the page (e.g. the page background or header), then continue. "
        "Never spend more than 2 attempts closing or reopening the same element; if it will "
        "not close, just navigate away to your next goal instead. "
    )
    if args.note:
        task += f"IMPORTANT site-specific instructions you must follow: {args.note}. "
    explore = args.explore
    if explore:
        task += (
            "AFTER logging in, crawl the whole authenticated app as thoroughly as a human tester. "
            "This is a DISPOSABLE TEST SITE: breaking it is fine, so act freely. "
            "1) Open EVERY item in every menu, sidebar/sidenav and account menu at least once "
            "(contact, complaint/feedback, chatbot, about, photo wall, membership/deluxe, orders, "
            "profile, addresses, payment, wallet, etc.) — visit them all, do not stop early. "
            "2) Use the SEARCH box with a real query (e.g. 'apple'). "
            "3) If the app sells anything, ADD items to the basket and COMPLETE A FULL CHECKOUT/ORDER "
            "(pick address + payment and place the order) — this reaches order/continue-code flows. "
            "4) If there is a LANGUAGE or locale switcher, change it. "
            "5) IF YOU SEE A FORM, fill a plausible sample string into EACH input/textarea field "
            "(never leave fields empty, never just retype into the search box) and click that form's "
            "own submit/send button: feedback, complaint, contact, review, comment, profile forms. "
            "You MAY buy, checkout, submit, and modify records. Only do NOT log out (keep your "
            "session alive to the end). Finish once every menu section has been visited and every "
            "reachable form submitted."
        )
    # generate_gif -> annotated per-step replay (screenshot + the action/goal for each click)
    agent = Agent(task=task, llm=llm, browser=session,
                  generate_gif=str(RES / "agent_history.gif"))
    await agent.run(max_steps=80 if explore else 25)

    await session.event_bus.dispatch(SaveStorageStateEvent(path=str(OUT)))
    await asyncio.sleep(1)
    await session.kill()

    # Playwright names the session video with a random guid; rename the newest one to match
    # this run's output (e.g. crawl_around_active_v2_1.mp4) so video and JSON share a name.
    if args.video_name:
        vids = sorted(rec_dir.glob("*.mp4"), key=lambda p: p.stat().st_mtime)
        if vids:
            dest = rec_dir / f"{args.video_name}.mp4"
            vids[-1].rename(dest)
            print(f"video -> {dest}")

    # --- proof ---
    if not OUT.exists():
        sys.exit("FAIL: no storage_state.json was written.")
    state = json.loads(OUT.read_text())
    cookies = state.get("cookies", [])
    origins = state.get("origins", [])
    ls_keys = [i["name"] for o in origins for i in o.get("localStorage", [])]
    print("\n===== PROOF =====")
    print(f"wrote: {OUT}")
    print(f"cookies: {len(cookies)} ({', '.join(c['name'] for c in cookies) or 'none'})")
    print(f"origins with storage: {len(origins)}")
    print(f"localStorage keys: {ls_keys or 'none'}")
    has_auth = "token" in ls_keys or any(
        c["name"].lower() in ("token", "session", "connect.sid", "jwt") for c in cookies
    )
    print(f"auth token present: {has_auth}")
    print("=================")
    sys.exit(0 if has_auth else 2)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="browser-use login (+explore) -> storage_state.json + gif + video")
    ap.add_argument("--url", default=DEFAULT_URL, help="target URL to test")
    ap.add_argument("--email", "--username", dest="email", default=DEFAULT_EMAIL, help="login email/username")
    ap.add_argument("--password", default=DEFAULT_PASSWORD, help="login password")
    ap.add_argument("--note", default=os.getenv("APP_NOTE", ""),
                    help="extra site-specific steps appended to the agent task, "
                         "e.g. \"dismiss the popup before entering creds\"")
    ap.add_argument("--proxy", default=os.getenv("CRAWL_PROXY", ""),
                    help="route the browser through this proxy (e.g. ZAP http://127.0.0.1:8080) so it captures the session")
    ap.add_argument("--explore", action="store_true",
                    default=os.getenv("EXPLORE", "").lower() in ("1", "true", "yes"),
                    help="after login, click around read-only to reveal more pages")
    ap.add_argument("--headless", action="store_true",
                    default=os.getenv("HEADLESS", "").lower() in ("1", "true", "yes"),
                    help="hide the browser window")
    ap.add_argument("--video-name", dest="video_name", default="",
                    help="rename the session recording to <name>.mp4 (match the run's JSON name)")
    asyncio.run(main(ap.parse_args()))

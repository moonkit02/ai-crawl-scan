"""
Crawling-expert agent: logs into a web app, then crawls it like a thorough human tester
to reveal as many pages/states as possible (target ~80% breadth, not 100%).

The crawling behaviour is a PERSONA injected via extend_system_message (see CRAWLER_DESIGN.md),
kept deliberately GENERAL so it does not overfit to one app. Per-site tweaks go in --note.

Optionally routes the browser through a proxy (e.g. ZAP) so the crawl traffic is captured
for scanning:  --proxy http://127.0.0.1:8080

Config: LLM_BASE_URL / LLM_API_KEY / LLM_MODEL in .env (same as bu_auth_proof.py).
Run:
    uv run python crawl_agent.py --url https://webapp3.wimify.xyz \
        --username bu-proof@test.local --password 'BUproof!234'
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

from sse_gateway_llm import ChatSSEGateway

load_dotenv(Path(__file__).parent / ".env")
load_dotenv()

RES = Path(__file__).parent.parent / "resources"   # repo-root/resources (this file lives in crawl/)
RES.mkdir(exist_ok=True)
OUT = RES / "storage_state.json"

# --- the crawling-expert persona (general, not app-specific). See CRAWLER_DESIGN.md. ---
CRAWLER_PERSONA = """
You are a methodical, curious human QA and security tester exploring an unfamiliar web
application. Everything you do flows through a security scanner (ZAP) that will then ATTACK
the HTTP requests it observes from you. Your job is to GENERATE AS MANY DISTINCT,
PARAMETERISED REQUESTS AS POSSIBLE so the scanner has real endpoints and inputs to test:
open every page (GET requests) AND, above all, fill and SUBMIT every form you can find
(POST/PUT requests carrying parameters). Aim for about 80% of the reachable app.

Coverage:
- On each page, note every menu item, link, button, tab, input and form.
- Go breadth-first: visit each top-level section once before going deep into any one.
- Keep a running memory of pages and forms already done and those still to try. Prefer new,
  unseen content; do not keep returning to the same place.
- Open detail views (list rows, cards, table entries, profiles). Expand accordions, switch
  tabs, open/close dialogs and menus. Handle pagination, "load more" and infinite scroll.

SUBMIT EVERY FORM — this is the priority, not an afterthought:
- Find every input, textarea, select and form on every page and SUBMIT it at least once.
  Examples: search boxes, "leave a review" / star-rating forms, comments, feedback, contact
  forms, newsletter/subscribe, filters, profile fields, any text field with a nearby button.
- Fill ALL fields of a form with realistic, plausible TEST values that match the field type:
  a real-looking name, a valid email format, a sensible number or date, and review/comment
  text that reads like a person wrote it. Then submit the form. Never use real personal data.
- Where a form takes free input, submit it more than once with different values to create
  extra distinct requests. Every submitted form is one more endpoint the scanner can attack.

Safety (you still submit forms aggressively, but avoid these):
- Do NOT log out, delete records, buy/checkout/pay, or change your own password or email in
  a way that locks you out of the session. Skip anything irreversible or account-destroying.
- Posting reviews, comments, feedback, searches and similar content IS wanted, so do it.

Staying unstuck and efficient:
- To close a sidebar/overlay/dialog with no close button, press Escape or click a neutral
  empty area, then continue. Never spend more than 2 tries on the same element; move on.
- If a page errors or is blank, go back and continue elsewhere. If recent actions produced
  no new content, change strategy or jump to the next unvisited area.

Finishing:
- Stop when most sections are covered, every reachable form has been submitted at least once,
  and no new navigation appears. In your final answer, list the pages you covered and the
  forms you submitted.
""".strip()


def build_task(url: str, email: str, password: str, note: str) -> str:
    task = (
        f"Go to {url}. Dismiss any welcome/cookie banner. "
        f"Log in with username/email '{email}' and password '{password}': find the login form "
        f"(it may be behind an Account/Login menu), enter the credentials and submit. Confirm you "
        f"are logged in. THEN crawl the whole authenticated application as described in your role: "
        f"visit every section AND fill and SUBMIT every form you can find (search, reviews, "
        f"comments, feedback, contact, profile, filters) with realistic test data, to generate "
        f"parameterised requests for the security scanner. Cover about 80% of the app. Avoid only "
        f"destructive/irreversible actions (logout, delete, purchase, password change)."
    )
    if note:
        task += f" IMPORTANT site-specific instructions you must follow: {note}."
    return task


async def main(args: argparse.Namespace) -> None:
    base_url = os.getenv("LLM_BASE_URL"); api_key = os.getenv("LLM_API_KEY"); model = os.getenv("LLM_MODEL")
    if not (base_url and api_key and model):
        sys.exit("Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env")
    llm = ChatSSEGateway(model=model, base_url=base_url.rstrip("/"), api_key=api_key, temperature=0.0)

    rec_dir = RES / "recordings"; rec_dir.mkdir(exist_ok=True)
    OUT.unlink(missing_ok=True)  # start logged out
    profile = BrowserProfile(
        headless=args.headless,
        storage_state=str(OUT),
        user_data_dir=None,
        record_video_dir=str(rec_dir),
        proxy=ProxySettings(server=args.proxy) if args.proxy else None,
        disable_security=bool(args.proxy),   # ignore cert for a MITM proxy like ZAP
    )
    session = BrowserSession(browser_profile=profile)

    agent = Agent(
        task=build_task(args.url, args.email, args.password, args.note),
        llm=llm,
        browser=session,
        extend_system_message=CRAWLER_PERSONA,   # <-- the crawling-expert persona
        generate_gif=str(RES / "agent_history.gif"),
    )
    history = await agent.run(max_steps=args.max_steps)

    await session.event_bus.dispatch(SaveStorageStateEvent(path=str(OUT)))
    await asyncio.sleep(1)
    await session.kill()

    # --- coverage report ---
    urls = [u for u in history.urls() if u]
    uniq = sorted(set(urls))
    actions = history.action_names()
    typed = sum(1 for a in actions if "input" in a.lower())            # fields typed into
    clicks = sum(1 for a in actions if a.lower() == "click_element_by_index" or a.lower() == "click")
    (RES / "crawl_urls.json").write_text(json.dumps(uniq, indent=2))
    print("\n===== CRAWL COVERAGE =====")
    print(f"steps taken       : {history.number_of_steps()}")
    print(f"unique pages seen : {len(uniq)}")
    print(f"fields typed into : {typed}   (proxy for forms exercised)")
    print(f"clicks            : {clicks}")
    print(f"logged in / token : {OUT.exists() and 'token' in OUT.read_text()}")
    for u in uniq[:30]:
        print(f"  {u}")
    if len(uniq) > 30:
        print(f"  ... (+{len(uniq)-30} more in resources/crawl_urls.json)")
    print(f"final result: {history.final_result()}")
    print("==========================")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Crawling-expert agent: login + human-like crawl")
    ap.add_argument("--url", default=os.getenv("TARGET_URL", "https://webapp3.wimify.xyz"))
    ap.add_argument("--email", "--username", dest="email", default=os.getenv("APP_EMAIL", "bu-proof@test.local"))
    ap.add_argument("--password", default=os.getenv("APP_PASSWORD", "BUproof!234"))
    ap.add_argument("--note", default=os.getenv("APP_NOTE", ""), help="extra site-specific guidance for the agent")
    ap.add_argument("--proxy", default=os.getenv("CRAWL_PROXY", ""), help="route browser through this proxy, e.g. ZAP http://127.0.0.1:8080")
    ap.add_argument("--max-steps", type=int, default=int(os.getenv("CRAWL_MAX_STEPS", "60")), dest="max_steps")
    ap.add_argument("--headless", action="store_true", default=os.getenv("HEADLESS", "").lower() in ("1", "true", "yes"))
    asyncio.run(main(ap.parse_args()))

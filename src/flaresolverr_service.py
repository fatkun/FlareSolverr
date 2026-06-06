import asyncio
import base64
import concurrent.futures
import logging
import platform
import time
from datetime import timedelta
from html import escape
from urllib.parse import unquote, quote

import browser_loop
import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]

# Turnstile token written by the widget once solved (standalone widgets)
TURNSTILE_TOKEN_SELECTOR = "input[name='cf-turnstile-response']"

# Selectors that locate the Turnstile challenge iframe. Playwright pierces the
# closed shadow DOM and cross-origin iframe that Cloudflare uses, so locating
# and clicking the checkbox works natively (this is what undetected-chromedriver
# could not do).
TURNSTILE_IFRAME_SELECTORS = [
    'iframe[src*="challenges.cloudflare.com"]',
    'iframe[src*="turnstile"]',
    'iframe[title*="Cloudflare"]',
    'iframe[title*="widget"]',
    'iframe[title*="Widget"]',
]

TURNSTILE_CHECKBOX_SELECTORS = [
    'input[type="checkbox"]',
    '.cb-lb input[type="checkbox"]',
    'label input[type="checkbox"]',
]

CLOUDFLARE_CHALLENGE_TITLES = [
    'Just a moment',
    'DDoS-Guard',
    'Attention Required'
]

CLOUDFLARE_CHALLENGE_SELECTORS = [
    '#challenge-stage',
    '#challenge-form',
    '#challenge-body-text',
    '#cf-challenge-running',
    '#cf-please-wait',
    '#challenge-spinner',
    '#turnstile-wrapper',
    '.ray_id',
    '.attack-box',
    '.lds-ring',
    'div[class*="challenge"]',
    'div[id*="challenge"]',
]

# Strong, Cloudflare-specific signals used to decide whether the interstitial is
# STILL active. Intentionally narrower than CLOUDFLARE_CHALLENGE_SELECTORS to
# avoid matching legitimate "challenge" elements on the real page (false
# negatives that would make the solver think the page never cleared).
CLOUDFLARE_ACTIVE_SELECTORS = [
    '#challenge-stage',
    '#challenge-running',
    '#cf-challenge-running',
    '#cf-please-wait',
    '#challenge-spinner',
    '#turnstile-wrapper',
]

# Resource types blocked when disableMedia is enabled (images / CSS / fonts).
BLOCKED_RESOURCE_TYPES = {'image', 'media', 'font', 'stylesheet'}

MAX_TURNSTILE_ATTEMPTS = 30
MAX_TURNSTILE_CLICKS = 10
SESSIONS_STORAGE = SessionsStorage()


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())
    logging.info("Launching web browser (camoufox)...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.debug(f"Response => POST /v1 body: {utils.object_to_dict(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


async def _new_transient_browser(proxy):
    """Create a throw-away camoufox browser + context for a single request."""
    cf, browser = await utils.launch_camoufox(proxy)
    context = await browser.new_context()
    return cf, browser, context


async def _close_transient(cf, browser, context):
    try:
        await context.close()
    except Exception:
        pass
    await utils.stop_camoufox(cf, browser)


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    timeout = int(req.maxTimeout) / 1000  # seconds

    if req.session:
        session_id = req.session
        ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
        session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

        if fresh:
            logging.debug(f"new session created to perform the request (session_id={session_id})")
        else:
            logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                          f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")
        try:
            return browser_loop.run_coro(_evil_logic(req, session.context, method), timeout)
        except concurrent.futures.TimeoutError:
            raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
        except Exception as e:
            raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))

    # transient browser (no session): create, use and destroy it on the loop
    cf = browser = context = None
    try:
        cf, browser, context = browser_loop.run_coro(_new_transient_browser(req.proxy), timeout)
        logging.debug('New camoufox browser has been created to perform the request')
        return browser_loop.run_coro(_evil_logic(req, context, method), timeout)
    except concurrent.futures.TimeoutError:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if cf is not None:
            try:
                browser_loop.run_coro(_close_transient(cf, browser, context))
                logging.debug('The used camoufox browser has been destroyed')
            except Exception as e:
                logging.debug(f'Error destroying camoufox browser: {e}')


def _normalize_cookies(cookies, url):
    """Convert FlareSolverr/Selenium-style cookies to Playwright add_cookies format."""
    normalized = []
    for c in cookies:
        nc = {'name': c.get('name'), 'value': c.get('value', '')}
        if c.get('domain'):
            nc['domain'] = c['domain']
            nc['path'] = c.get('path', '/')
        else:
            nc['url'] = url
        normalized.append(nc)
    return normalized


async def _block_media_route(route):
    try:
        if route.request.resource_type in BLOCKED_RESOURCE_TYPES:
            await route.abort()
        else:
            await route.continue_()
    except Exception:
        try:
            await route.continue_()
        except Exception:
            pass


async def _read_turnstile_token(page):
    try:
        locator = page.locator(TURNSTILE_TOKEN_SELECTOR)
        count = await locator.count()
    except Exception as e:
        logging.debug(f"Turnstile token locator failed: {e}")
        return None

    for index in range(count):
        try:
            token = await locator.nth(index).input_value(timeout=500)
            if token:
                logging.info(f"Turnstile token extracted from input #{index}")
                return token
        except Exception as e:
            logging.debug(f"Turnstile token input #{index} check failed: {e}")
    return None


async def _get_turnstile_frame(page):
    """Return the Cloudflare challenge frame from the browser frame tree.

    The Turnstile iframe is nested inside a CLOSED shadow root, so DOM queries
    (``page.locator('iframe')``) cannot reach it. ``page.frames`` is built from
    the browser frame tree and lists the frame regardless of shadow DOM, which
    is exactly what undetected-chromedriver could not do.
    """
    candidates = [f for f in page.frames
                  if 'challenges.cloudflare.com' in (f.url or '') or 'turnstile' in (f.url or '')]
    if not candidates:
        return None
    for f in candidates:
        if 'turnstile' in (f.url or ''):
            return f
    return candidates[0]


async def _coordinate_click_frame(page, frame) -> bool:
    """Click the checkbox area of the Turnstile widget by coordinates.

    Works even when the iframe lives in a closed shadow root: ``frame_element()``
    resolves the owning ``<iframe>`` via the frame tree, then we click at page
    (viewport) coordinates with a real, trusted mouse event.
    """
    try:
        handle = await frame.frame_element()
        try:
            await handle.scroll_into_view_if_needed(timeout=2000)
        except Exception:
            pass
        box = await handle.bounding_box()
    except Exception as e:
        logging.debug(f"Resolving Turnstile iframe element failed: {e}")
        return False

    if not box or box['width'] <= 0 or box['height'] <= 0:
        logging.debug(f"Turnstile iframe has no usable bounding box: {box}")
        return False

    # The checkbox sits ~30px from the left edge, vertically centered
    x = box['x'] + 30
    y = box['y'] + box['height'] / 2
    try:
        await page.mouse.move(x, y)
        await page.mouse.click(x, y)
        logging.info(f"Coordinate-clicked Turnstile iframe at ({x:.0f},{y:.0f}), box={box}")
        return True
    except Exception as e:
        logging.debug(f"Coordinate click on Turnstile iframe failed: {e}")
        return False


async def _find_and_click_checkbox(page) -> bool:
    """Find the Turnstile challenge frame and click its checkbox."""
    frame = await _get_turnstile_frame(page)
    if frame is None:
        logging.debug("No Cloudflare challenge frame found in the frame tree")
        return False

    logging.debug(f"Found Cloudflare challenge frame: {frame.url}")

    # 1) deterministic coordinate click on the checkbox area — fast, handles the
    #    closed shadow DOM and reliably hits the Turnstile checkbox
    if await _coordinate_click_frame(page, frame):
        return True

    # 2) fallback: click the checkbox element inside the frame (short timeout)
    for checkbox_selector in TURNSTILE_CHECKBOX_SELECTORS:
        try:
            await frame.locator(checkbox_selector).first.click(timeout=1000)
            logging.info(f"Clicked Turnstile checkbox in frame via '{checkbox_selector}'")
            return True
        except Exception:
            continue

    # 3) fallback: click the frame body (the whole widget is often clickable)
    try:
        await frame.locator('body').click(timeout=1000)
        logging.info("Clicked Turnstile frame body")
        return True
    except Exception:
        return False


async def _safe_click(page, selector: str) -> bool:
    try:
        await page.locator(selector).first.click(timeout=1000)
        return True
    except Exception:
        return False


async def _try_click_strategies(page) -> bool:
    if await _find_and_click_checkbox(page):
        return True

    for selector in ['.cf-turnstile', 'iframe[src*="turnstile"]', '[data-sitekey]', '*[class*="turnstile"]']:
        if await _safe_click(page, selector):
            logging.info(f"Clicked Turnstile via selector '{selector}'")
            return True

    try:
        await page.evaluate("document.querySelector('.cf-turnstile')?.click()")
    except Exception:
        pass
    return False


async def _challenge_still_present(page) -> bool:
    """True while a Cloudflare interstitial / Turnstile widget is on the page."""
    try:
        title = (await page.title()) or ''
        for challenge_title in CLOUDFLARE_CHALLENGE_TITLES:
            if challenge_title.lower() in title.lower():
                return True
    except Exception:
        # title read can fail mid-navigation; assume still working
        return True

    for selector in TURNSTILE_IFRAME_SELECTORS + CLOUDFLARE_ACTIVE_SELECTORS:
        try:
            if await page.locator(selector).count() > 0:
                return True
        except Exception:
            continue
    return False


async def _detect_challenge_reasons(page) -> list:
    reasons = []
    try:
        title = (await page.title()) or ''
        for challenge_title in CLOUDFLARE_CHALLENGE_TITLES:
            if challenge_title.lower() in title.lower():
                reasons.append(f"title contains '{challenge_title}'")
    except Exception as e:
        logging.debug(f"Challenge title detection failed: {e}")

    detection_selectors = [TURNSTILE_TOKEN_SELECTOR] + TURNSTILE_IFRAME_SELECTORS + CLOUDFLARE_CHALLENGE_SELECTORS
    seen = set()
    for selector in detection_selectors:
        if selector in seen:
            continue
        seen.add(selector)
        try:
            if await page.locator(selector).count() > 0:
                reasons.append(f"selector '{selector}' matched")
        except Exception as e:
            logging.debug(f"Detection selector '{selector}' failed: {e}")

    try:
        body_text = await page.evaluate(
            "() => document.body ? document.body.innerText.slice(0, 2000) : ''")
        body_text_lower = (body_text or '').lower()
        for marker in [
            'verify you are human',
            'checking your browser',
            'checking if the site connection is secure',
            'needs to review the security of your connection',
            'turnstile'
        ]:
            if marker in body_text_lower:
                reasons.append(f"body text contains '{marker}'")
    except Exception as e:
        logging.debug(f"Challenge body text detection failed: {e}")

    return reasons


async def _has_cf_clearance(context, url=None) -> bool:
    """True once Cloudflare has issued the cf_clearance cookie (challenge passed)."""
    try:
        cookies = await context.cookies(url) if url else await context.cookies()
    except Exception:
        return False
    for c in cookies:
        if c.get('name') == 'cf_clearance' and c.get('value'):
            return True
    return False


async def _wait_for_real_page(page, max_wait: int = 8):
    """After Cloudflare accepts the challenge it reloads to the real page; wait
    for that navigation to settle so we capture the real content, not the
    transitional challenge page."""
    for _ in range(max_wait):
        if not await _challenge_still_present(page):
            try:
                await page.wait_for_load_state('domcontentloaded', timeout=2000)
            except Exception:
                pass
            return
        await asyncio.sleep(1)


async def _solve_challenge(page, context, url=None):
    """Click the Turnstile until the challenge is passed or a token appears.

    Returns ``(turnstile_token, cleared)``. Success is determined primarily by
    the ``cf_clearance`` cookie (the definitive signal that Cloudflare accepted
    the challenge), and secondarily by the interstitial disappearing.
    """
    click_count = 0
    for attempt in range(MAX_TURNSTILE_ATTEMPTS):
        logging.info(
            f"Turnstile solve attempt {attempt + 1}/{MAX_TURNSTILE_ATTEMPTS} "
            f"(clicks: {click_count}/{MAX_TURNSTILE_CLICKS})")

        # strongest success signal: Cloudflare issued cf_clearance
        if await _has_cf_clearance(context, url):
            logging.info("cf_clearance cookie detected — challenge passed")
            await _wait_for_real_page(page)
            return await _read_turnstile_token(page), True

        # secondary signal: the interstitial is gone
        if not await _challenge_still_present(page):
            logging.info("Challenge interstitial no longer present")
            await _wait_for_real_page(page)
            return await _read_turnstile_token(page), True

        # standalone widget on a normal page: a token alone means solved
        token = await _read_turnstile_token(page)
        if token:
            return token, False

        if click_count < MAX_TURNSTILE_CLICKS and (attempt == 1 or (attempt > 2 and attempt % 3 == 0)):
            logging.info(f"Trying Turnstile click #{click_count + 1}/{MAX_TURNSTILE_CLICKS}")
            if await _try_click_strategies(page):
                logging.info(f"Turnstile click succeeded (#{click_count + 1}/{MAX_TURNSTILE_CLICKS})")
            else:
                logging.info(f"All Turnstile click strategies failed on attempt {attempt + 1}")
            click_count += 1

        await asyncio.sleep(min(0.5 + attempt * 0.05, 2.0))

    cleared = await _has_cf_clearance(context, url) or not await _challenge_still_present(page)
    if cleared:
        await _wait_for_real_page(page)
    return await _read_turnstile_token(page), cleared


async def _post_request(req: V1RequestBase, page, timeout_ms: int):
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData and req.postData[0] != '?' \
        else req.postData[1:] if req.postData else ''
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value = value.replace('"', '&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    await page.goto("data:text/html;charset=utf-8," + quote(html_content),
                    wait_until='domcontentloaded', timeout=timeout_ms)


async def _evil_logic(req: V1RequestBase, context, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    timeout_ms = int(req.maxTimeout)

    # decide whether to block resources like images/css/fonts
    disable_media = utils.get_config_disable_media()
    if req.disableMedia is not None:
        disable_media = req.disableMedia

    page = None
    routed = False
    try:
        if disable_media:
            logging.debug("Blocking media resources (images, CSS, fonts)")
            await context.route("**/*", _block_media_route)
            routed = True

        page = await context.new_page()

        # navigate to the page
        logging.debug(f"Navigating to... {req.url}")
        if method == 'POST':
            await _post_request(req, page, timeout_ms)
        else:
            await page.goto(req.url, wait_until='domcontentloaded', timeout=timeout_ms)

        # set cookies if required, then reload
        if req.cookies is not None and len(req.cookies) > 0:
            logging.debug('Setting cookies...')
            await context.add_cookies(_normalize_cookies(req.cookies, req.url))
            if method == 'POST':
                await _post_request(req, page, timeout_ms)
            else:
                await page.goto(req.url, wait_until='domcontentloaded', timeout=timeout_ms)

        # give the challenge widget a moment to mount
        await asyncio.sleep(1)

        if utils.get_config_log_html():
            logging.debug(f"Response HTML:\n{await page.content()}")

        page_title = await page.title()
        logging.info(f"Page loaded. title='{page_title}', url='{page.url}'")

        # find access denied titles
        for title in ACCESS_DENIED_TITLES:
            if page_title.startswith(title):
                raise Exception('Cloudflare has blocked this request. '
                                'Probably your IP is banned for this site, check in your web browser.')
        # find access denied selectors
        for selector in ACCESS_DENIED_SELECTORS:
            try:
                if await page.locator(selector).count() > 0:
                    raise Exception('Cloudflare has blocked this request. '
                                    'Probably your IP is banned for this site, check in your web browser.')
            except Exception as e:
                if 'Cloudflare has blocked' in str(e):
                    raise

        turnstile_token = None
        challenge_reasons = await _detect_challenge_reasons(page)
        if challenge_reasons:
            logging.info("Challenge detected. Reasons: " + "; ".join(challenge_reasons[:10]))
            if len(challenge_reasons) > 10:
                logging.info(f"Challenge detection has {len(challenge_reasons) - 10} more reason(s)")
            logging.info("Solving challenge (Playwright Turnstile click)...")
            turnstile_token, cleared = await _solve_challenge(page, context, req.url)
            if cleared or turnstile_token:
                logging.info("Challenge solved!")
                res.message = "Challenge solved!"
            else:
                logging.info("Challenge not solved after click strategies")
                res.message = "Challenge detected but not solved!"
        else:
            logging.info("Challenge not detected!")
            res.message = "Challenge not detected!"

        challenge_res = ChallengeResolutionResultT({})
        challenge_res.url = page.url
        challenge_res.status = 200  # todo: Playwright main response status could be captured
        challenge_res.cookies = await context.cookies()
        user_agent = await page.evaluate("() => navigator.userAgent")
        challenge_res.userAgent = user_agent
        if utils.USER_AGENT is None:
            utils.USER_AGENT = user_agent
        challenge_res.turnstile_token = turnstile_token

        if not req.returnOnlyCookies:
            challenge_res.headers = {}  # todo: Playwright response headers could be captured

            if req.waitInSeconds and req.waitInSeconds > 0:
                logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
                await asyncio.sleep(req.waitInSeconds)

            challenge_res.response = await page.content()

        if req.returnScreenshot:
            screenshot_bytes = await page.screenshot()
            challenge_res.screenshot = base64.b64encode(screenshot_bytes).decode('ascii')

        res.result = challenge_res
        return res
    finally:
        if routed:
            try:
                await context.unroute("**/*", _block_media_route)
            except Exception:
                pass
        if page is not None:
            try:
                await page.close()
            except Exception:
                pass

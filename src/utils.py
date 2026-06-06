import json
import logging
import os

from camoufox.async_api import AsyncCamoufox

import browser_loop

FLARESOLVERR_VERSION = None
PLATFORM_VERSION = None
USER_AGENT = None


def get_config_log_html() -> bool:
    return os.environ.get('LOG_HTML', 'false').lower() == 'true'


def get_config_headless() -> bool:
    return os.environ.get('HEADLESS', 'true').lower() == 'true'


def get_config_disable_media() -> bool:
    return os.environ.get('DISABLE_MEDIA', 'false').lower() == 'true'


def get_config_humanize() -> bool:
    # human-like cursor movement helps pass Cloudflare; set HUMANIZE=false to disable
    return os.environ.get('HUMANIZE', 'true').lower() == 'true'


def get_flaresolverr_version() -> str:
    global FLARESOLVERR_VERSION
    if FLARESOLVERR_VERSION is not None:
        return FLARESOLVERR_VERSION

    package_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, 'package.json')
    if not os.path.isfile(package_path):
        package_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'package.json')
    with open(package_path) as f:
        FLARESOLVERR_VERSION = json.loads(f.read())['version']
        return FLARESOLVERR_VERSION


def get_current_platform() -> str:
    global PLATFORM_VERSION
    if PLATFORM_VERSION is not None:
        return PLATFORM_VERSION
    PLATFORM_VERSION = os.name
    return PLATFORM_VERSION


def _camoufox_proxy(proxy: dict):
    """Map a FlareSolverr proxy dict to a Playwright/camoufox proxy dict.

    FlareSolverr uses ``{'url', 'username', 'password'}``; camoufox (Playwright)
    expects ``{'server', 'username', 'password'}``. Authenticated proxies are
    handled natively, so the old Chrome proxy-auth extension is no longer needed.
    """
    if not proxy or 'url' not in proxy:
        return None
    pw_proxy = {'server': proxy['url']}
    if proxy.get('username'):
        pw_proxy['username'] = proxy['username']
    if proxy.get('password'):
        pw_proxy['password'] = proxy['password']
    return pw_proxy


async def launch_camoufox(proxy: dict = None):
    """Start a camoufox (Firefox) browser on the background loop.

    Returns ``(camoufox_instance, browser)`` where ``browser`` is a Playwright
    ``Browser``. The camoufox instance is kept so it can be stopped later via
    :func:`stop_camoufox`. ``humanize`` enables human-like cursor movement which
    materially improves Cloudflare pass rates.
    """
    logging.debug('Launching camoufox browser...')
    kwargs = {'headless': get_config_headless(), 'humanize': get_config_humanize()}
    pw_proxy = _camoufox_proxy(proxy)
    if pw_proxy:
        kwargs['proxy'] = pw_proxy
    cf = AsyncCamoufox(**kwargs)
    browser = await cf.start()
    return cf, browser


async def stop_camoufox(cf, browser=None):
    """Stop a camoufox instance started with :func:`launch_camoufox`."""
    try:
        # AsyncCamoufox is an async context manager; start() == __aenter__
        await cf.__aexit__(None, None, None)
    except Exception as e:
        logging.debug("Error stopping camoufox (%s); closing browser directly", e)
        if browser is not None:
            try:
                await browser.close()
            except Exception:
                pass


def get_user_agent() -> str:
    """Return the browser User-Agent, launching a one-off camoufox if needed."""
    global USER_AGENT
    if USER_AGENT is not None:
        return USER_AGENT

    async def _probe():
        cf, browser = await launch_camoufox()
        try:
            context = await browser.new_context()
            page = await context.new_page()
            ua = await page.evaluate("() => navigator.userAgent")
            await context.close()
            return ua
        finally:
            await stop_camoufox(cf, browser)

    try:
        USER_AGENT = browser_loop.run_coro(_probe())
        return USER_AGENT
    except Exception as e:
        raise Exception("Error getting browser User-Agent. " + str(e))


def object_to_dict(_object):
    json_dict = json.loads(json.dumps(_object, default=lambda o: o.__dict__))
    # remove hidden fields
    return {k: v for k, v in json_dict.items() if not k.startswith('__')}

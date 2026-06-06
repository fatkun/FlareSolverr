"""Background asyncio event loop used to drive camoufox / Playwright.

Playwright objects (Browser / BrowserContext / Page) are bound to the event
loop that created them and must always be used from that same loop. FlareSolverr
is a synchronous, multi-threaded WSGI app (waitress) and historically ran each
request through ``func_timeout`` on a throw-away thread, so there is no single
thread we can pin browsers to.

This module owns ONE long-lived event loop running in a daemon thread. Every
browser is created and used on that loop; the synchronous request threads only
submit coroutines to it via :func:`run_coro` and block on the result. The
``future.result(timeout)`` call also replaces ``func_timeout`` for honouring the
``maxTimeout`` request parameter.
"""

import asyncio
import concurrent.futures
import logging
import os
import threading

_LOOP: asyncio.AbstractEventLoop = None
_THREAD: threading.Thread = None
_LOCK = threading.Lock()


def _run_loop(ready: threading.Event):
    global _LOOP
    # Playwright spawns the browser as a subprocess; on Windows that requires a
    # Proactor event loop (the default Selector loop cannot do subprocesses).
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _LOOP = loop
    ready.set()
    loop.run_forever()


def get_loop() -> asyncio.AbstractEventLoop:
    """Return the shared background loop, starting it on first use."""
    global _THREAD
    if _LOOP is None:
        with _LOCK:
            if _LOOP is None:
                ready = threading.Event()
                _THREAD = threading.Thread(
                    target=_run_loop, args=(ready,), name='camoufox-loop', daemon=True)
                _THREAD.start()
                ready.wait()
    return _LOOP


def run_coro(coro, timeout: float = None):
    """Submit *coro* to the background loop and block until it finishes.

    Raises ``concurrent.futures.TimeoutError`` if it does not complete within
    *timeout* seconds; the coroutine is cancelled so its own ``finally`` blocks
    run and the browser gets cleaned up.
    """
    loop = get_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise


def shutdown():
    """Stop the background loop (best-effort; used on process exit)."""
    global _LOOP, _THREAD
    if _LOOP is not None:
        try:
            _LOOP.call_soon_threadsafe(_LOOP.stop)
        except Exception as e:
            logging.debug("Error stopping browser loop: %s", e)
        if _THREAD is not None:
            _THREAD.join(timeout=5)
        _LOOP = None
        _THREAD = None

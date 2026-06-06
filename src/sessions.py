import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid1

import browser_loop
import utils


@dataclass
class Session:
    session_id: str
    cf_instance: object  # camoufox AsyncCamoufox handle (for teardown)
    browser: object      # playwright Browser
    context: object      # long-lived playwright BrowserContext (keeps cookies across requests)
    created_at: datetime

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at


async def _create_session_objects(proxy: Optional[dict]):
    cf, browser = await utils.launch_camoufox(proxy)
    context = await browser.new_context()
    return cf, browser, context


async def _close_session_objects(session: Session):
    try:
        await session.context.close()
    except Exception:
        pass
    await utils.stop_camoufox(session.cf_instance, session.browser)


class SessionsStorage:
    """SessionsStorage creates, stores and process all the sessions"""

    def __init__(self):
        self.sessions = {}

    def create(self, session_id: Optional[str] = None, proxy: Optional[dict] = None,
               force_new: Optional[bool] = False) -> Tuple[Session, bool]:
        """create creates a new camoufox browser if necessary, assigns the
        defined (or newly generated) session_id to it and returns the session
        object. If a new session has been created the second argument is True.

        Note: The function is idempotent, so if session_id already exists a new
        browser won't be created and the existing session will be returned.
        """
        session_id = session_id or str(uuid1())

        if force_new:
            self.destroy(session_id)

        if self.exists(session_id):
            return self.sessions[session_id], False

        cf, browser, context = browser_loop.run_coro(_create_session_objects(proxy))
        created_at = datetime.now()
        session = Session(session_id, cf, browser, context, created_at)

        self.sessions[session_id] = session

        return session, True

    def exists(self, session_id: str) -> bool:
        return session_id in self.sessions

    def destroy(self, session_id: str) -> bool:
        """destroy closes the browser instance and removes the session from the
        storage. The function is noop if session_id doesn't exist. Returns True
        if the session was found and destroyed, False otherwise.
        """
        if not self.exists(session_id):
            return False

        session = self.sessions.pop(session_id)
        try:
            browser_loop.run_coro(_close_session_objects(session))
        except Exception as e:
            logging.debug(f"Error closing session (session_id={session_id}): {e}")
        return True

    def get(self, session_id: str, ttl: Optional[timedelta] = None) -> Tuple[Session, bool]:
        session, fresh = self.create(session_id)

        if ttl is not None and not fresh and session.lifetime() > ttl:
            logging.debug(f'session\'s lifetime has expired, so the session is recreated (session_id={session_id})')
            session, fresh = self.create(session_id, force_new=True)

        return session, fresh

    def session_ids(self) -> list[str]:
        return list(self.sessions.keys())

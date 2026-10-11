import logging
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from pif.settings import Settings
from pif.observability import content_preview, logger


class SessionError(ValueError):
    pass


@dataclass
class Session:
    owner: str
    touched: float
    turns: deque = field(default_factory=lambda: deque(maxlen=8))
    # Decaying accumulated risk (v6.0): after every scan the session keeps
    # 75% of this value and adds 25% of the scan's fused risk. Two or more
    # consecutive risky turns keep the memory high, so a mild follow-up turn
    # that repeats earlier probing still escalates.
    risk_memory: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)


class SessionStore:
    def __init__(self, settings: Settings, clock=time.monotonic):
        self.settings, self.clock = settings, clock
        self.sessions = {}
        self.lock = threading.Lock()

    def prune(self):
        with self.lock:
            now = self.clock()
            previous_count = len(self.sessions)
            self.sessions = {
                key: value
                for key, value in self.sessions.items()
                if now - value.touched < self.settings.session_ttl or value.lock.locked()
            }
            logger.debug("session.expiry_checked", extra={"event_fields": dict(removed_sessions=previous_count - len(self.sessions), active_sessions=len(self.sessions))})

    def acquire(self, session_id: str | None, owner: str):
        logger.debug("session.lookup_started", extra={"event_fields": dict(reused=session_id is not None)})
        with self.lock:
            now = self.clock()
            self.sessions = {
                key: value
                for key, value in self.sessions.items()
                if now - value.touched < self.settings.session_ttl or value.lock.locked()
            }
            if session_id is None:
                if len(self.sessions) >= self.settings.max_sessions:
                    logger.warning("session.lookup_rejected", extra={"event_fields": dict(reason="capacity")})
                    raise SessionError("session_capacity_exceeded")
                session_id = secrets.token_urlsafe(24)
                self.sessions[session_id] = Session(owner=owner, touched=now)
                logger.info("session.created", extra={"event_fields": dict(active_sessions=len(self.sessions))})
            session = self.sessions.get(session_id)
            if session is None or session.owner != owner:
                logger.warning("session.lookup_rejected", extra={"event_fields": dict(reason="unknown_expired_or_wrong_owner")})
                raise SessionError("unknown_or_expired_session")
            if not session.lock.acquire(blocking=False):
                logger.warning("session.lookup_rejected", extra={"event_fields": dict(reason="busy")})
                raise SessionError("session_busy")
            session.touched = now
            return session_id, session

    def release(self, session: Session):
        with self.lock:
            session.touched = self.clock()
            session.lock.release()
            logger.debug("session.released", extra={"event_fields": dict(retained_turns=len(session.turns))})

    def reset(self, session_id: str, owner: str):
        with self.lock:
            session = self.sessions.get(session_id)
            if session is None or session.owner != owner:
                raise SessionError("unknown_session")
            if session.lock.locked():
                raise SessionError("session_busy")
            del self.sessions[session_id]
            logger.info("session.cleared", extra={"event_fields": dict(remaining_sessions=len(self.sessions))})

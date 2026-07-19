"""Incident- and seat-scoped Agents SDK sessions."""

from __future__ import annotations

import hashlib
import inspect
from pathlib import Path

from agents import SQLiteSession

from crosspatch.domain.enums import Seat


class IncidentSessionStore:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[tuple[str, ...], SQLiteSession] = {}

    def for_seat(self, incident_id: str, seat: Seat) -> SQLiteSession:
        key = ("seat", incident_id, seat.value)
        session = self._sessions.get(key)
        if session is None:
            incident_digest = hashlib.sha256(incident_id.encode("utf-8")).hexdigest()[:24]
            session = SQLiteSession(
                f"incident-{incident_digest}-seat-{seat.name.lower()}",
                db_path=self._database_path,
            )
            self._sessions[key] = session
        return session

    def for_transition(
        self,
        incident_id: str,
        source: Seat,
        target: Seat,
    ) -> SQLiteSession:
        """Return a session isolated from both participating seat sessions."""

        key = ("transition", incident_id, source.value, target.value)
        session = self._sessions.get(key)
        if session is None:
            incident_digest = hashlib.sha256(incident_id.encode("utf-8")).hexdigest()[:24]
            session = SQLiteSession(
                (
                    f"incident-{incident_digest}-transition-"
                    f"{source.name.lower()}-{target.name.lower()}"
                ),
                db_path=self._database_path,
            )
            self._sessions[key] = session
        return session

    async def close(self) -> None:
        sessions = tuple(self._sessions.values())
        self._sessions.clear()
        for session in sessions:
            result = session.close()
            if inspect.isawaitable(result):
                await result

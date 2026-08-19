"""Change windows and freeze periods.

A change can be correct and still be the wrong thing to do: pushing it during
month-end close or in the middle of a business day is how a fix becomes the
incident. The gate therefore asks when as well as whether.

Windows are written as `mon-fri 22:00-04:00; sat,sun 00:00-06:00` and freezes as
`2026-12-20..2027-01-02; 2026-11-27`, both evaluated in `CHANGE_WINDOW_TZ`. No
windows configured means always open, so the control is opt-in rather than a
surprise. A freeze always wins over a window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WINDOW_RE = re.compile(
    r"^(?P<days>[a-z,\-]+)\s+(?P<start>\d{1,2}:\d{2})\s*-\s*(?P<end>\d{1,2}:\d{2})$",
    re.IGNORECASE,
)


class ScheduleError(ValueError):
    """A schedule that cannot be parsed. Refusing to start beats guessing."""


@dataclass(frozen=True)
class Window:
    days: frozenset[int]
    start: time
    end: time

    @property
    def wraps(self) -> bool:
        return self.end <= self.start

    def contains(self, moment: datetime) -> bool:
        weekday = moment.weekday()
        clock = moment.time()
        if not self.wraps:
            return weekday in self.days and self.start <= clock < self.end
        # An overnight window belongs to the day it started on.
        if weekday in self.days and clock >= self.start:
            return True
        return (weekday - 1) % 7 in self.days and clock < self.end


@dataclass
class WindowDecision:
    open: bool
    reason: str = ""
    next_open: str = ""


def _parse_days(text: str) -> frozenset[int]:
    days: set[int] = set()
    for part in text.lower().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, _, last = part.partition("-")
            if first not in DAYS or last not in DAYS:
                raise ScheduleError(f"unknown day range '{part}'")
            start, end = DAYS.index(first), DAYS.index(last)
            span = range(start, end + 1) if start <= end else [*range(start, 7), *range(end + 1)]
            days.update(span)
        else:
            if part not in DAYS:
                raise ScheduleError(f"unknown day '{part}'")
            days.add(DAYS.index(part))
    if not days:
        raise ScheduleError("a window needs at least one day")
    return frozenset(days)


def _parse_time(text: str) -> time:
    hour, _, minute = text.partition(":")
    try:
        return time(int(hour), int(minute))
    except ValueError as exc:
        raise ScheduleError(f"invalid time '{text}'") from exc


def parse_windows(spec: str) -> list[Window]:
    windows: list[Window] = []
    for chunk in (spec or "").split(";"):
        text = chunk.strip()
        if not text:
            continue
        match = WINDOW_RE.match(text)
        if not match:
            raise ScheduleError(
                f"cannot read change window '{text}'; expected 'mon-fri 22:00-04:00'"
            )
        windows.append(
            Window(
                days=_parse_days(match.group("days")),
                start=_parse_time(match.group("start")),
                end=_parse_time(match.group("end")),
            )
        )
    return windows


def parse_freezes(spec: str) -> list[tuple[date, date]]:
    periods: list[tuple[date, date]] = []
    for chunk in (spec or "").split(";"):
        text = chunk.strip()
        if not text:
            continue
        first, separator, last = text.partition("..")
        try:
            start = date.fromisoformat(first.strip())
            end = date.fromisoformat(last.strip()) if separator else start
        except ValueError as exc:
            raise ScheduleError(
                f"cannot read freeze period '{text}'; expected 'YYYY-MM-DD' or a '..' range"
            ) from exc
        if end < start:
            raise ScheduleError(f"freeze period '{text}' ends before it starts")
        periods.append((start, end))
    return periods


class ChangeSchedule:
    def __init__(self, windows: str = "", freezes: str = "", timezone: str = "UTC") -> None:
        self.windows = parse_windows(windows)
        self.freezes = parse_freezes(freezes)
        try:
            self.tz = ZoneInfo(timezone or "UTC")
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ScheduleError(f"unknown timezone '{timezone}'") from exc
        self.timezone = timezone or "UTC"

    @property
    def configured(self) -> bool:
        return bool(self.windows or self.freezes)

    def describe(self) -> str:
        if not self.configured:
            return "no change windows configured; changes may be approved at any time"
        parts = []
        if self.windows:
            parts.append(f"{len(self.windows)} window(s)")
        if self.freezes:
            parts.append(f"{len(self.freezes)} freeze period(s)")
        return f"{', '.join(parts)} in {self.timezone}"

    def _local(self, moment: datetime | None) -> datetime:
        return (moment or datetime.now(self.tz)).astimezone(self.tz)

    def _frozen(self, day: date) -> tuple[date, date] | None:
        for start, end in self.freezes:
            if start <= day <= end:
                return (start, end)
        return None

    def evaluate(self, moment: datetime | None = None) -> WindowDecision:
        now = self._local(moment)

        freeze = self._frozen(now.date())
        if freeze is not None:
            start, end = freeze
            span = start.isoformat() if start == end else f"{start.isoformat()}..{end.isoformat()}"
            return WindowDecision(
                open=False,
                reason=f"a change freeze is in effect ({span}, {self.timezone})",
                next_open=(end + timedelta(days=1)).isoformat(),
            )

        if not self.windows:
            return WindowDecision(open=True)

        if any(window.contains(now) for window in self.windows):
            return WindowDecision(open=True)

        return WindowDecision(
            open=False,
            reason=(
                f"outside the approved change window "
                f"({now.strftime('%a %H:%M')} {self.timezone})"
            ),
            next_open=self._next_open(now),
        )

    def _next_open(self, now: datetime, horizon_days: int = 14) -> str:
        """The next moment a window starts and no freeze applies."""
        candidates: list[datetime] = []
        for offset in range(horizon_days + 1):
            day = now.date() + timedelta(days=offset)
            if self._frozen(day):
                continue
            for window in self.windows:
                if day.weekday() not in window.days:
                    continue
                candidate = datetime.combine(day, window.start, tzinfo=self.tz)
                if candidate > now:
                    candidates.append(candidate)
        return min(candidates).isoformat() if candidates else ""

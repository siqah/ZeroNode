"""Change windows and freeze periods."""

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from app.schedule import ChangeSchedule, ScheduleError, parse_windows

LONDON = ZoneInfo("Europe/London")


def at(text: str, tz=LONDON) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=tz)


def test_no_configuration_means_always_open():
    schedule = ChangeSchedule()
    assert schedule.configured is False
    assert schedule.evaluate(at("2026-08-19T14:00")).open is True


def test_a_window_admits_only_its_own_hours():
    schedule = ChangeSchedule(windows="mon-fri 22:00-23:30", timezone="Europe/London")
    assert schedule.evaluate(at("2026-08-19T22:30")).open is True
    assert schedule.evaluate(at("2026-08-19T14:00")).open is False
    # Saturday is not in the window, whatever the hour.
    assert schedule.evaluate(at("2026-08-22T22:30")).open is False


def test_an_overnight_window_belongs_to_the_day_it_started_on():
    schedule = ChangeSchedule(windows="fri 22:00-04:00", timezone="Europe/London")
    assert schedule.evaluate(at("2026-08-21T23:00")).open is True  # Friday night
    assert schedule.evaluate(at("2026-08-22T02:00")).open is True  # into Saturday
    assert schedule.evaluate(at("2026-08-22T05:00")).open is False
    assert schedule.evaluate(at("2026-08-23T02:00")).open is False  # Sunday morning


def test_the_boundaries_are_start_inclusive_and_end_exclusive():
    schedule = ChangeSchedule(windows="wed 22:00-23:00", timezone="Europe/London")
    assert schedule.evaluate(at("2026-08-19T22:00")).open is True
    assert schedule.evaluate(at("2026-08-19T23:00")).open is False


def test_a_freeze_beats_an_open_window():
    schedule = ChangeSchedule(
        windows="mon-sun 00:00-23:59",
        freezes="2026-12-20..2027-01-02",
        timezone="Europe/London",
    )
    decision = schedule.evaluate(at("2026-12-24T22:30"))
    assert decision.open is False
    assert "freeze" in decision.reason
    assert decision.next_open == "2027-01-03"
    assert schedule.evaluate(at("2027-01-03T10:00")).open is True


def test_a_single_date_freeze_covers_that_day():
    schedule = ChangeSchedule(freezes="2026-11-27", timezone="Europe/London")
    assert schedule.evaluate(at("2026-11-27T03:00")).open is False
    assert schedule.evaluate(at("2026-11-28T03:00")).open is True


def test_a_closed_window_says_when_it_next_opens():
    schedule = ChangeSchedule(windows="sat 01:00-05:00", timezone="Europe/London")
    decision = schedule.evaluate(at("2026-08-19T14:00"))  # a Wednesday
    assert decision.open is False
    assert decision.next_open.startswith("2026-08-22T01:00")
    assert "Wed 14:00" in decision.reason


def test_the_timezone_is_the_configured_one_not_the_servers():
    schedule = ChangeSchedule(windows="mon-fri 22:00-23:00", timezone="Europe/London")
    # 21:30 UTC is 22:30 in London during British Summer Time.
    assert schedule.evaluate(datetime.fromisoformat("2026-08-19T21:30+00:00")).open is True


def test_day_lists_and_wrapping_ranges_parse():
    assert len(parse_windows("sat,sun 00:00-06:00")[0].days) == 2
    assert parse_windows("fri-mon 22:00-04:00")[0].days == frozenset({4, 5, 6, 0})


def test_several_windows_can_be_listed():
    schedule = ChangeSchedule(
        windows="mon-fri 22:00-04:00; sat,sun 08:00-18:00", timezone="Europe/London"
    )
    assert schedule.evaluate(at("2026-08-19T23:00")).open is True
    assert schedule.evaluate(at("2026-08-22T12:00")).open is True
    assert schedule.evaluate(at("2026-08-22T20:00")).open is False


@pytest.mark.parametrize(
    "spec", ["someday 22:00-04:00", "mon 25:00-04:00", "mon 22:00", "mon-fri"]
)
def test_an_unreadable_window_fails_at_configuration_time(spec):
    with pytest.raises(ScheduleError):
        ChangeSchedule(windows=spec)


@pytest.mark.parametrize("spec", ["not-a-date", "2026-13-01", "2027-01-02..2026-12-20"])
def test_an_unreadable_freeze_fails_at_configuration_time(spec):
    with pytest.raises(ScheduleError):
        ChangeSchedule(freezes=spec)


def test_an_unknown_timezone_fails_at_configuration_time():
    with pytest.raises(ScheduleError):
        ChangeSchedule(windows="mon 22:00-23:00", timezone="Mars/Olympus")

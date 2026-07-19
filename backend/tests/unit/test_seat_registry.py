from crosspatch.domain.enums import Effort, Seat
from crosspatch.domain.seats import SEAT_SPECS


def test_exact_seat_order_models_and_initial_efforts():
    assert [(spec.seat, spec.model, spec.initial_effort) for spec in SEAT_SPECS] == [
        (Seat.PROSECUTOR, "gpt-5.6-luna", Effort.LOW),
        (Seat.INSPECTOR, "gpt-5.6-terra", Effort.MEDIUM),
        (Seat.COUNSEL, "gpt-5.6-terra", Effort.MEDIUM),
        (Seat.MAGISTRATE, "gpt-5.6-sol", Effort.MEDIUM),
        (Seat.BAILIFF, "gpt-5.6-luna", Effort.NONE),
    ]


def test_exact_effort_ladders_and_escalation_policy():
    by_seat = {spec.seat: spec for spec in SEAT_SPECS}
    assert by_seat[Seat.PROSECUTOR].effort_ladder == (Effort.LOW, Effort.MEDIUM, Effort.HIGH)
    assert by_seat[Seat.INSPECTOR].effort_ladder == (
        Effort.MEDIUM,
        Effort.HIGH,
        Effort.XHIGH,
    )
    assert by_seat[Seat.COUNSEL].effort_ladder == (
        Effort.MEDIUM,
        Effort.HIGH,
        Effort.XHIGH,
    )
    assert by_seat[Seat.MAGISTRATE].effort_ladder == (
        Effort.MEDIUM,
        Effort.HIGH,
        Effort.XHIGH,
    )
    assert by_seat[Seat.MAGISTRATE].human_escalation_only is True
    assert by_seat[Seat.BAILIFF].effort_ladder == (Effort.NONE,)
    assert by_seat[Seat.BAILIFF].max_escalations == 0
    assert all(spec.tier_rationale and spec.role for spec in SEAT_SPECS)

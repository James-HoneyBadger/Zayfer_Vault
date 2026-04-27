"""GUI smoke tests for the password-strength meter widget.

These tests gate themselves on PySide6 + pytest-qt being importable so
the suite still passes in headless / CI environments that don't ship Qt.
The first batch exercises the pure scoring helper (no event loop); the
second batch boots the actual ``QWidget`` via ``qtbot`` and asserts the
visible label updates as the password text changes.
"""

from __future__ import annotations

import os
import sys

import pytest

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

PySide6 = pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

# Headless Qt: required on most CI hosts and OK locally.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Importing the module pulls in PySide6.QtWidgets, which in turn requires
# a QApplication to exist before any QWidget is constructed. ``pytest-qt``
# provides one via the ``qtbot`` fixture, so we defer the import until
# inside the tests.


def test_calculate_strength_empty_password() -> None:
    from hb_zayfer.gui.password_strength import PasswordStrengthMeter

    score, label = PasswordStrengthMeter._calculate_strength("")
    assert score == 0
    assert label == "No password"


def test_calculate_strength_strong_password_scores_high() -> None:
    from hb_zayfer.gui.password_strength import PasswordStrengthMeter

    score, _label = PasswordStrengthMeter._calculate_strength(
        "Tr0ub4dor&3-Correct-Horse-Battery-Staple!"
    )
    assert score >= 80


def test_calculate_strength_weak_password_scores_low() -> None:
    from hb_zayfer.gui.password_strength import PasswordStrengthMeter

    score, _label = PasswordStrengthMeter._calculate_strength("password")
    assert score < 40


def test_password_strength_widget_updates(qtbot) -> None:  # type: ignore[no-untyped-def]
    """Boot the widget under qtbot and verify it reacts to input."""
    if sys.platform == "darwin" and not os.environ.get("DISPLAY"):
        pytest.skip("macOS headless Qt is unreliable in CI")

    from hb_zayfer.gui.password_strength import PasswordStrengthMeter

    widget = PasswordStrengthMeter()
    qtbot.addWidget(widget)
    widget.update_strength("")
    empty_text = widget.strength_label.text()
    widget.update_strength("Tr0ub4dor&3-Correct-Horse-Battery-Staple!")
    strong_text = widget.strength_label.text()
    assert empty_text != strong_text

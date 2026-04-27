"""Smoke tests for the Keyboard Shortcuts dialog.

Boots the dialog via pytest-qt and asserts it lists every shortcut row
and exposes accessibility metadata. Skipped automatically when PySide6
or pytest-qt is not importable.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

PySide6 = pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_shortcuts_dialog_lists_all_rows(qtbot) -> None:
    from hb_zayfer.gui.shortcuts_dialog import SHORTCUTS, ShortcutsDialog

    dialog = ShortcutsDialog()
    qtbot.addWidget(dialog)

    # Find the table and verify it has one row per registered shortcut.
    from PySide6.QtWidgets import QTableWidget

    tables = dialog.findChildren(QTableWidget)
    assert len(tables) == 1, "Expected exactly one shortcuts table"
    table = tables[0]
    assert table.rowCount() == len(SHORTCUTS)
    assert table.columnCount() == 2

    # First row should match the first SHORTCUTS entry.
    first_key, first_desc = SHORTCUTS[0]
    assert table.item(0, 0).text() == first_key
    assert table.item(0, 1).text() == first_desc


def test_shortcuts_dialog_has_accessibility_metadata(qtbot) -> None:
    from hb_zayfer.gui.shortcuts_dialog import ShortcutsDialog

    dialog = ShortcutsDialog()
    qtbot.addWidget(dialog)

    assert dialog.accessibleName() == "Keyboard Shortcuts dialog"

    from PySide6.QtWidgets import QTableWidget

    table = dialog.findChild(QTableWidget)
    assert table is not None
    assert table.accessibleName() == "Shortcuts table"
    assert table.accessibleDescription() != ""

"""Password / passphrase generator view."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QTabWidget,
    QApplication,
    QMessageBox,
)

import hb_zayfer as hbz
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.theme import Theme


class PasswordGenView(QWidget):
    """Generate random passwords and passphrases."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        tabs = QTabWidget()
        tabs.addTab(self._build_password_tab(), "Random Password")
        tabs.addTab(self._build_passphrase_tab(), "Passphrase")
        layout.addWidget(tabs)

        # Output area (shared)
        out_box = QGroupBox("Generated Output")
        out_layout = QVBoxLayout(out_box)

        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(38)
        self.output.setStyleSheet("font-family: monospace; font-size: 14px;")
        out_layout.addWidget(self.output)

        self.entropy_label = QLabel("Entropy: —")
        out_layout.addWidget(self.entropy_label)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self._copy_output)
        btn_row.addWidget(copy_btn)

        regen_btn = QPushButton("Regenerate")
        regen_btn.clicked.connect(self._regenerate)
        btn_row.addWidget(regen_btn)

        btn_row.addStretch()
        out_layout.addLayout(btn_row)
        layout.addWidget(out_box)

        layout.addStretch()

        # Track which tab is active
        self._active_tab = "password"
        tabs.currentChanged.connect(self._on_tab_changed)

    def _build_password_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length:"))
        self.pw_length = QSpinBox()
        self.pw_length.setRange(4, 128)
        self.pw_length.setValue(20)
        len_row.addWidget(self.pw_length)
        len_row.addStretch()
        layout.addLayout(len_row)

        self.pw_upper = QCheckBox("Uppercase (A-Z)")
        self.pw_upper.setChecked(True)
        layout.addWidget(self.pw_upper)

        self.pw_lower = QCheckBox("Lowercase (a-z)")
        self.pw_lower.setChecked(True)
        layout.addWidget(self.pw_lower)

        self.pw_digits = QCheckBox("Digits (0-9)")
        self.pw_digits.setChecked(True)
        layout.addWidget(self.pw_digits)

        self.pw_symbols = QCheckBox("Symbols (!@#$...)")
        self.pw_symbols.setChecked(True)
        layout.addWidget(self.pw_symbols)

        excl_row = QHBoxLayout()
        excl_row.addWidget(QLabel("Exclude:"))
        self.pw_exclude = QLineEdit()
        self.pw_exclude.setPlaceholderText("Characters to exclude (e.g. 0OlI1)")
        excl_row.addWidget(self.pw_exclude)
        layout.addLayout(excl_row)

        gen_btn = QPushButton("Generate Password")
        gen_btn.clicked.connect(self._gen_password)
        layout.addWidget(gen_btn)

        layout.addStretch()
        return w

    def _build_passphrase_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        words_row = QHBoxLayout()
        words_row.addWidget(QLabel("Word count:"))
        self.pp_words = QSpinBox()
        self.pp_words.setRange(3, 20)
        self.pp_words.setValue(6)
        words_row.addWidget(self.pp_words)
        words_row.addStretch()
        layout.addLayout(words_row)

        sep_row = QHBoxLayout()
        sep_row.addWidget(QLabel("Separator:"))
        self.pp_sep = QComboBox()
        self.pp_sep.addItems(["-", " ", ".", "_", "/"])
        self.pp_sep.setEditable(True)
        sep_row.addWidget(self.pp_sep)
        sep_row.addStretch()
        layout.addLayout(sep_row)

        gen_btn = QPushButton("Generate Passphrase")
        gen_btn.clicked.connect(self._gen_passphrase)
        layout.addWidget(gen_btn)

        layout.addStretch()
        return w

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_tab_changed(self, index: int) -> None:
        self._active_tab = "password" if index == 0 else "passphrase"

    def _gen_password(self) -> None:
        try:
            pw = hbz.generate_password(
                length=self.pw_length.value(),
                uppercase=self.pw_upper.isChecked(),
                lowercase=self.pw_lower.isChecked(),
                digits=self.pw_digits.isChecked(),
                symbols=self.pw_symbols.isChecked(),
                exclude=self.pw_exclude.text(),
            )
            self.output.setText(pw)
            entropy = hbz.password_entropy(
                length=self.pw_length.value(),
                uppercase=self.pw_upper.isChecked(),
                lowercase=self.pw_lower.isChecked(),
                digits=self.pw_digits.isChecked(),
                symbols=self.pw_symbols.isChecked(),
            )
            self.entropy_label.setText(f"Entropy: {entropy:.1f} bits")
            self._color_entropy(entropy)
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def _gen_passphrase(self) -> None:
        try:
            sep = self.pp_sep.currentText()
            word_count = self.pp_words.value()
            phrase = hbz.generate_passphrase(words=word_count, separator=sep)
            self.output.setText(phrase)
            entropy = hbz.passphrase_entropy(word_count=word_count)
            self.entropy_label.setText(f"Entropy: {entropy:.1f} bits")
            self._color_entropy(entropy)
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def _regenerate(self) -> None:
        if self._active_tab == "password":
            self._gen_password()
        else:
            self._gen_passphrase()

    def _copy_output(self) -> None:
        text = self.output.text()
        if not text:
            return
        secure_copy(text)
        self._notify("show_success", "Password copied to clipboard")

    def _color_entropy(self, bits: float) -> None:
        """Color the entropy label based on strength."""
        if bits >= 128:
            color = "#28a745"  # green
            strength = "Excellent"
        elif bits >= 80:
            color = "#17a2b8"  # teal
            strength = "Strong"
        elif bits >= 60:
            color = "#ffc107"  # yellow
            strength = "Moderate"
        else:
            color = "#dc3545"  # red
            strength = "Weak"
        self.entropy_label.setText(f"Entropy: {bits:.1f} bits — {strength}")
        self.entropy_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _notify(self, method: str, message: str) -> None:
        w = self.window()
        if hasattr(w, "notifications"):
            getattr(w.notifications, method)(message)

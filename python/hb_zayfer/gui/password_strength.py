"""Password strength indicator widget."""

from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel, QProgressBar


class PasswordStrengthMeter(QWidget):
    """Visual indicator of password strength with color-coded progress bar."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(8)

        self.strength_label = QLabel("No password")
        self.strength_label.setStyleSheet("font-size: 11px; color: #666;")

        layout.addWidget(self.strength_label)
        layout.addWidget(self.strength_bar, 1)

    def update_strength(self, password: str) -> None:
        """Update the meter based on password strength."""
        if not password:
            self.strength_bar.setValue(0)
            self.strength_label.setText("No password")
            self.strength_bar.setStyleSheet("")
            return

        score, strength_text = self._calculate_strength(password)
        self.strength_bar.setValue(score)
        self.strength_label.setText(strength_text)

        # Color code based on strength
        if score < 30:
            color = "#e74c3c"  # red
        elif score < 60:
            color = "#e67e22"  # orange
        elif score < 80:
            color = "#f39c12"  # yellow
        else:
            color = "#27ae60"  # green

        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)

    @staticmethod
    def _calculate_strength(password: str) -> tuple[int, str]:
        """
        Calculate password strength score (0-100) and descriptive text.
        
        Scoring:
        - Length: base score
        - Character variety: bonus points
        - Patterns: penalty points
        - Common passwords: major penalty
        """
        if not password:
            return 0, "No password"

        score = 0

        # Length scoring
        length = len(password)
        if length < 8:
            score += length * 5  # Max 35 for 7 chars
        elif length < 12:
            score += 40 + (length - 8) * 5  # 40-55
        elif length < 16:
            score += 60 + (length - 12) * 5  # 60-75
        else:
            score += 80 + min((length - 16) * 2, 20)  # 80-100

        # Character variety bonuses
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        score += variety_count * 5

        # Penalties for common patterns
        if re.match(r'^[a-z]+$', password) or re.match(r'^[A-Z]+$', password):
            score -= 10  # Only letters
        if re.match(r'^\d+$', password):
            score -= 20  # Only digits
        if re.search(r'(.)\1{2,}', password):
            score -= 10  # Repeated characters (aaa, 111)
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
            score -= 10  # Sequential patterns

        # Common password check (simple list)
        common = [
            'password', '12345678', 'qwerty', 'abc123', 'monkey', 'letmein',
            'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'shadow', 'superman', 'qazwsx', 'michael',
        ]
        if password.lower() in common:
            score = max(10, score - 40)

        # Cap score at 0-100
        score = max(0, min(100, score))

        # Determine strength text
        if score < 30:
            strength_text = "Very Weak"
        elif score < 50:
            strength_text = "Weak"
        elif score < 70:
            strength_text = "Fair"
        elif score < 85:
            strength_text = "Good"
        else:
            strength_text = "Strong"

        return score, strength_text

    @staticmethod
    def get_strength_advice(password: str) -> str:
        """Get advice for improving password strength."""
        if not password:
            return "Enter a password to see strength analysis."

        advice = []
        
        if len(password) < 12:
            advice.append("• Use at least 12 characters")
        
        if not re.search(r'[a-z]', password):
            advice.append("• Add lowercase letters")
        if not re.search(r'[A-Z]', password):
            advice.append("• Add uppercase letters")
        if not re.search(r'\d', password):
            advice.append("• Add numbers")
        if not re.search(r'[^a-zA-Z0-9]', password):
            advice.append("• Add special characters (!@#$%^&*)")
        
        if re.search(r'(.)\1{2,}', password):
            advice.append("• Avoid repeated characters")
        
        if re.search(r'(012|123|234|345|456|567|678|789)', password):
            advice.append("• Avoid sequential numbers")
        
        if re.search(r'(abc|bcd|cde|def)', password.lower()):
            advice.append("• Avoid sequential letters")

        if not advice:
            return "✓ Strong password!"
        
        return "Suggestions:\n" + "\n".join(advice)

"""About dialog for the application."""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QTextBrowser
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

import hb_zayfer as hbz


class AboutDialog(QDialog):
    """About dialog showing application information."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Zayfer Vault")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title
        title = QLabel("🔐 Zayfer Vault")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Version
        version = QLabel(f"Version {hbz.version()}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #888888; font-size: 14px;")
        layout.addWidget(version)
        
        # Description
        desc = QTextBrowser()
        desc.setOpenExternalLinks(True)
        desc.setMaximumHeight(200)
        desc.setHtml("""
            <div style='font-size: 13px; line-height: 1.6;'>
            <h3>Encryption Suite</h3>
            <p><b>Zayfer Vault</b> is a comprehensive encryption suite implementing modern cryptographic
            primitives with a focus on security and usability.</p>
            
            <h4>Features:</h4>
            <ul>
                <li>Multiple encryption algorithms (AES-GCM, ChaCha20-Poly1305)</li>
                <li>RSA, Ed25519, and X25519 key management</li>
                <li>OpenPGP format support (Sequoia-OpenPGP)</li>
                <li>Secure file and text encryption/decryption</li>
                <li>Address book and keyring management</li>
                <li>Audit logging for cryptographic operations</li>
            </ul>
            </div>
        """)
        layout.addWidget(desc)
        
        # Credits
        credits = QLabel(
            "<b>Built with:</b><br>"
            "Rust (RustCrypto, Sequoia-OpenPGP) • Python • PySide6<br><br>"
            "<b>Author:</b> James Temple<br>"
            "<b>Email:</b> james@honey-badger.org"
        )
        credits.setAlignment(Qt.AlignmentFlag.AlignCenter)
        credits.setStyleSheet("font-size: 12px; color: #666666;")
        layout.addWidget(credits)
        
        # Copyright
        copyright_label = QLabel("© 2026 Honey Badger Universe")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        copyright_label.setStyleSheet("font-size: 11px; color: #888888;")
        layout.addWidget(copyright_label)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setMinimumWidth(100)
        close_btn.clicked.connect(self.accept)
        btn_layout = QVBoxLayout()
        btn_layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(btn_layout)

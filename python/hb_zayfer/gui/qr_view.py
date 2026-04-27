"""QR key exchange view — encode public keys as QR codes for easy sharing."""

from __future__ import annotations

import io

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QGroupBox,
    QTextEdit,
    QMessageBox,
    QFileDialog,
    QSplitter,
)

import hb_zayfer as hbz


def _generate_qr_pixmap(data: str, scale: int = 6) -> QPixmap | None:
    """Generate a QR code pixmap from *data* using segno."""
    try:
        import segno

        qr = segno.make(data, error="M")
        buf = io.BytesIO()
        qr.save(buf, kind="png", scale=scale, border=2)
        buf.seek(0)
        img = QImage()
        img.loadFromData(buf.read())
        return QPixmap.fromImage(img)
    except ImportError:
        return None
    except Exception:
        return None


class QRExchangeView(QWidget):
    """Generate and scan QR codes for sharing public keys."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Generate QR ──
        gen_box = QGroupBox("Share Your Public Key via QR")
        gen_layout = QVBoxLayout(gen_box)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Key:"))
        self.key_combo = QComboBox()
        self.key_combo.setMinimumWidth(350)
        key_row.addWidget(self.key_combo, 1)
        refresh_btn = QPushButton("↻")
        refresh_btn.setFixedWidth(32)
        refresh_btn.setToolTip("Refresh key list")
        refresh_btn.clicked.connect(self._refresh_keys)
        key_row.addWidget(refresh_btn)
        gen_layout.addLayout(key_row)

        btn_row = QHBoxLayout()
        gen_btn = QPushButton("Generate QR Code")
        gen_btn.clicked.connect(self._generate_qr)
        btn_row.addWidget(gen_btn)
        save_btn = QPushButton("Save QR as PNG")
        save_btn.clicked.connect(self._save_qr)
        btn_row.addWidget(save_btn)
        btn_row.addStretch()
        gen_layout.addLayout(btn_row)

        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumHeight(200)
        self.qr_label.setText("Select a key and click Generate QR Code")
        gen_layout.addWidget(self.qr_label)

        self.uri_display = QTextEdit()
        self.uri_display.setReadOnly(True)
        self.uri_display.setMaximumHeight(50)
        self.uri_display.setPlaceholderText("Key URI will appear here…")
        gen_layout.addWidget(self.uri_display)

        splitter.addWidget(gen_box)

        # ── Import from URI ──
        import_box = QGroupBox("Import Key from URI")
        import_layout = QVBoxLayout(import_box)

        import_layout.addWidget(
            QLabel("Paste a hbzf-key:// URI (from a scanned QR code) to import:")
        )
        self.import_input = QTextEdit()
        self.import_input.setMaximumHeight(60)
        self.import_input.setPlaceholderText("hbzf-key://ed25519/…")
        import_layout.addWidget(self.import_input)

        ibtn_row = QHBoxLayout()
        import_btn = QPushButton("Import Key")
        import_btn.clicked.connect(self._import_key)
        ibtn_row.addWidget(import_btn)
        ibtn_row.addStretch()
        import_layout.addLayout(ibtn_row)

        self.import_status = QLabel()
        import_layout.addWidget(self.import_status)

        splitter.addWidget(import_box)

        layout.addWidget(splitter)
        self._refresh_keys()

    # ------------------------------------------------------------------
    # Key list
    # ------------------------------------------------------------------

    def _refresh_keys(self) -> None:
        self.key_combo.clear()
        try:
            ks = hbz.KeyStore()
            for k in ks.list_keys():
                if k.has_public:
                    label = f"{k.label} ({k.algorithm}) [{k.fingerprint[:12]}…]"
                    self.key_combo.addItem(label, k.fingerprint)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Generate
    # ------------------------------------------------------------------

    def _generate_qr(self) -> None:
        idx = self.key_combo.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "No Key", "Select a key to share.")
            return

        fp = self.key_combo.currentData()
        try:
            ks = hbz.KeyStore()
            meta = ks.get_key(fp)
            pub_bytes = meta.public_key_bytes
            if pub_bytes is None:
                QMessageBox.warning(self, "Error", "Selected key has no public component.")
                return

            algo = meta.algorithm.lower().replace("-", "").replace("_", "")
            # Normalize to standard URI algo names
            algo_map = {
                "ed25519": "ed25519",
                "x25519": "x25519",
                "rsa2048": "rsa-2048",
                "rsa4096": "rsa-4096",
            }
            algo_name = algo_map.get(algo, meta.algorithm.lower())

            # Build URI manually (core function isn't exposed to Python yet)
            import base64

            b64 = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
            uri = f"hbzf-key://{algo_name}/{b64}"
            if meta.label:
                uri += f"?label={meta.label.replace(' ', '%20')}"

            self.uri_display.setPlainText(uri)
            self._current_uri = uri

            pixmap = _generate_qr_pixmap(uri)
            if pixmap:
                self.qr_label.setPixmap(
                    pixmap.scaled(
                        300,
                        300,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
            else:
                self.qr_label.setText(
                    "QR generation unavailable (install segno: pip install segno)"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _save_qr(self) -> None:
        if not hasattr(self, "_current_uri") or not self._current_uri:
            QMessageBox.warning(self, "No QR", "Generate a QR code first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save QR Code", "key_qr.png", "PNG Images (*.png)"
        )
        if not path:
            return

        try:
            import segno

            qr = segno.make(self._current_uri, error="M")
            qr.save(path, kind="png", scale=10, border=2)
            self._notify("show_success", f"QR saved to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Save Error", str(exc))

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def _import_key(self) -> None:
        uri = self.import_input.toPlainText().strip()
        if not uri.startswith("hbzf-key://"):
            QMessageBox.warning(
                self, "Invalid URI", "URI must start with hbzf-key://"
            )
            return

        try:
            # Parse URI
            rest = uri[len("hbzf-key://") :]
            path_part, _, query = rest.partition("?")
            algo, _, b64 = path_part.partition("/")

            import base64

            # Add padding
            pad = 4 - len(b64) % 4
            if pad < 4:
                b64 += "=" * pad
            pub_bytes = base64.urlsafe_b64decode(b64)

            label = None
            if query:
                for param in query.split("&"):
                    if param.startswith("label="):
                        label = param[6:].replace("%20", " ")

            display_label = label or f"Imported {algo}"
            self.import_status.setText(
                f"Parsed: {algo} key, {len(pub_bytes)} bytes"
                + (f", label: {display_label}" if label else "")
            )
            self.import_status.setStyleSheet("color: green;")

            QMessageBox.information(
                self,
                "Key Parsed",
                f"Algorithm: {algo}\n"
                f"Public key: {len(pub_bytes)} bytes\n"
                f"Label: {display_label}\n\n"
                "Use the Keyring view to import this key data.",
            )
        except Exception as exc:
            self.import_status.setText(f"Error: {exc}")
            self.import_status.setStyleSheet("color: red;")

    def _notify(self, method: str, message: str) -> None:
        w = self.window()
        if hasattr(w, "notifications"):
            getattr(w.notifications, method)(message)

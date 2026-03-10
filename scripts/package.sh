#!/usr/bin/env bash
# Build distributable packages for HB_Zayfer.
#
# Usage:
#   ./scripts/package.sh              # auto-detect platform
#   ./scripts/package.sh deb          # Debian/Ubuntu .deb
#   ./scripts/package.sh rpm          # Fedora/RHEL .rpm
#   ./scripts/package.sh arch         # Arch Linux PKGBUILD
#   ./scripts/package.sh appimage     # AppImage (Linux universal)
#   ./scripts/package.sh macos        # macOS .app bundle
#   ./scripts/package.sh wheel        # Python wheel (all platforms)
#   ./scripts/package.sh all          # All available for current OS

set -euo pipefail

VERSION="1.0.0"
NAME="hb-zayfer"
DESCRIPTION="A full-featured encryption/decryption suite"
MAINTAINER="James Temple <james@honey-badger.org>"
LICENSE="MIT"
URL="https://github.com/james/HB_Zayfer"

DIST_DIR="dist"
mkdir -p "$DIST_DIR"

# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────

log() { echo "==> $*"; }
err() { echo "ERROR: $*" >&2; exit 1; }

build_cli() {
    log "Building CLI binary (release)…"
    cargo build --release -p hb_zayfer_cli
    CLI_BIN="target/release/hb-zayfer"
    if [[ ! -f "$CLI_BIN" ]]; then
        CLI_BIN="target/release/hb_zayfer_cli"
    fi
    echo "$CLI_BIN"
}

build_wheel() {
    log "Building Python wheel…"
    if ! command -v maturin &>/dev/null; then
        err "maturin not found. Install with: pip install maturin"
    fi
    maturin build --release --out "$DIST_DIR"
    log "Wheel built in $DIST_DIR/"
}

# ──────────────────────────────────────────────────────────────────
# DEB (Debian/Ubuntu)
# ──────────────────────────────────────────────────────────────────

build_deb() {
    log "Building .deb package…"
    CLI_BIN=$(build_cli)

    ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    PKG_DIR="$DIST_DIR/deb-staging"
    rm -rf "$PKG_DIR"

    mkdir -p "$PKG_DIR/DEBIAN"
    mkdir -p "$PKG_DIR/usr/bin"
    mkdir -p "$PKG_DIR/usr/share/doc/$NAME"
    mkdir -p "$PKG_DIR/usr/share/man/man1"

    cp "$CLI_BIN" "$PKG_DIR/usr/bin/$NAME"
    chmod 755 "$PKG_DIR/usr/bin/$NAME"

    cp README.md "$PKG_DIR/usr/share/doc/$NAME/" 2>/dev/null || true
    cp CHANGELOG.md "$PKG_DIR/usr/share/doc/$NAME/" 2>/dev/null || true

    cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Description: $DESCRIPTION
 HB_Zayfer provides AES-256-GCM, ChaCha20-Poly1305, RSA, Ed25519,
 X25519, and OpenPGP cryptographic operations with a CLI, GUI, and
 web interface.
Homepage: $URL
EOF

    DEB_FILE="$DIST_DIR/${NAME}_${VERSION}_${ARCH}.deb"
    if command -v dpkg-deb &>/dev/null; then
        dpkg-deb --build "$PKG_DIR" "$DEB_FILE"
        log "Created $DEB_FILE"
    else
        log "dpkg-deb not available — staging directory ready at $PKG_DIR"
    fi
    rm -rf "$PKG_DIR"
}

# ──────────────────────────────────────────────────────────────────
# RPM (Fedora/RHEL)
# ──────────────────────────────────────────────────────────────────

build_rpm() {
    log "Building .rpm package…"
    CLI_BIN=$(build_cli)

    SPEC_DIR="$DIST_DIR/rpm-staging"
    rm -rf "$SPEC_DIR"
    mkdir -p "$SPEC_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Create tarball
    TAR_NAME="${NAME}-${VERSION}"
    TAR_DIR="$SPEC_DIR/SOURCES"
    mkdir -p "$TAR_DIR/$TAR_NAME"
    cp "$CLI_BIN" "$TAR_DIR/$TAR_NAME/$NAME"
    cp README.md "$TAR_DIR/$TAR_NAME/" 2>/dev/null || true
    (cd "$TAR_DIR" && tar czf "$TAR_NAME.tar.gz" "$TAR_NAME")
    rm -rf "$TAR_DIR/$TAR_NAME"

    cat > "$SPEC_DIR/SPECS/$NAME.spec" <<EOF
Name:           $NAME
Version:        $VERSION
Release:        1%{?dist}
Summary:        $DESCRIPTION
License:        $LICENSE
URL:            $URL
Source0:        %{name}-%{version}.tar.gz

%description
HB_Zayfer encryption suite providing AES-256-GCM, ChaCha20-Poly1305,
RSA, Ed25519, X25519, and OpenPGP operations.

%prep
%setup -q

%install
mkdir -p %{buildroot}%{_bindir}
install -m 755 $NAME %{buildroot}%{_bindir}/$NAME

%files
%{_bindir}/$NAME
%doc README.md

%changelog
* $(date +"%a %b %d %Y") $MAINTAINER - $VERSION-1
- Initial package
EOF

    if command -v rpmbuild &>/dev/null; then
        rpmbuild --define "_topdir $(pwd)/$SPEC_DIR" -bb "$SPEC_DIR/SPECS/$NAME.spec"
        find "$SPEC_DIR/RPMS" -name "*.rpm" -exec cp {} "$DIST_DIR/" \;
        log "RPM built in $DIST_DIR/"
    else
        log "rpmbuild not available — spec file ready at $SPEC_DIR/SPECS/$NAME.spec"
    fi
    rm -rf "$SPEC_DIR"
}

# ──────────────────────────────────────────────────────────────────
# Arch Linux PKGBUILD
# ──────────────────────────────────────────────────────────────────

build_arch() {
    log "Generating Arch Linux PKGBUILD…"
    build_cli >/dev/null

    cat > "$DIST_DIR/PKGBUILD" <<'EOF'
# Maintainer: James Temple <james@honey-badger.org>
pkgname=hb-zayfer
pkgver=1.0.0
pkgrel=1
pkgdesc="A full-featured encryption/decryption suite"
arch=('x86_64' 'aarch64')
url="https://github.com/james/HB_Zayfer"
license=('MIT')
depends=()
makedepends=('rust' 'cargo')

build() {
    cd "$srcdir/.."
    cargo build --release -p hb_zayfer_cli
}

package() {
    cd "$srcdir/.."
    install -Dm755 "target/release/hb-zayfer" "$pkgdir/usr/bin/hb-zayfer" ||
    install -Dm755 "target/release/hb_zayfer_cli" "$pkgdir/usr/bin/hb-zayfer"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
    install -Dm644 CHANGELOG.md "$pkgdir/usr/share/doc/$pkgname/CHANGELOG.md" 2>/dev/null || true
}
EOF
    log "PKGBUILD created at $DIST_DIR/PKGBUILD"
}

# ──────────────────────────────────────────────────────────────────
# AppImage (Linux universal)
# ──────────────────────────────────────────────────────────────────

build_appimage() {
    log "Building AppImage…"
    CLI_BIN=$(build_cli)

    APP_DIR="$DIST_DIR/AppDir"
    rm -rf "$APP_DIR"
    mkdir -p "$APP_DIR/usr/bin"
    mkdir -p "$APP_DIR/usr/share/icons/hicolor/256x256/apps"

    cp "$CLI_BIN" "$APP_DIR/usr/bin/$NAME"
    chmod 755 "$APP_DIR/usr/bin/$NAME"

    # Desktop entry
    cat > "$APP_DIR/$NAME.desktop" <<EOF
[Desktop Entry]
Name=HB Zayfer
Comment=$DESCRIPTION
Exec=$NAME
Icon=$NAME
Type=Application
Categories=Utility;Security;
EOF

    # AppRun script
    cat > "$APP_DIR/AppRun" <<'APPRUN'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/hb-zayfer" "$@"
APPRUN
    chmod 755 "$APP_DIR/AppRun"

    if command -v appimagetool &>/dev/null; then
        APPIMAGE_FILE="$DIST_DIR/${NAME}-${VERSION}-$(uname -m).AppImage"
        appimagetool "$APP_DIR" "$APPIMAGE_FILE"
        log "AppImage created at $APPIMAGE_FILE"
    else
        log "appimagetool not available — AppDir ready at $APP_DIR/"
        log "Install: https://github.com/AppImage/AppImageKit/releases"
    fi
}

# ──────────────────────────────────────────────────────────────────
# macOS .app bundle
# ──────────────────────────────────────────────────────────────────

build_macos() {
    log "Building macOS .app bundle…"
    CLI_BIN=$(build_cli)

    APP_BUNDLE="$DIST_DIR/HB Zayfer.app"
    rm -rf "$APP_BUNDLE"
    mkdir -p "$APP_BUNDLE/Contents/MacOS"
    mkdir -p "$APP_BUNDLE/Contents/Resources"

    cp "$CLI_BIN" "$APP_BUNDLE/Contents/MacOS/$NAME"
    chmod 755 "$APP_BUNDLE/Contents/MacOS/$NAME"

    cat > "$APP_BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>HB Zayfer</string>
    <key>CFBundleIdentifier</key>
    <string>org.honey-badger.hb-zayfer</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleExecutable</key>
    <string>$NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

    log "App bundle created at $APP_BUNDLE"

    # Optionally create DMG
    if command -v hdiutil &>/dev/null; then
        DMG_FILE="$DIST_DIR/${NAME}-${VERSION}.dmg"
        hdiutil create -volname "HB Zayfer" -srcfolder "$APP_BUNDLE" -ov "$DMG_FILE"
        log "DMG created at $DMG_FILE"
    fi
}

# ──────────────────────────────────────────────────────────────────
# Dispatch
# ──────────────────────────────────────────────────────────────────

case "${1:-auto}" in
    deb)       build_deb ;;
    rpm)       build_rpm ;;
    arch)      build_arch ;;
    appimage)  build_appimage ;;
    macos)     build_macos ;;
    wheel)     build_wheel ;;
    all)
        build_wheel
        case "$(uname -s)" in
            Linux)
                build_deb
                build_rpm
                build_arch
                build_appimage
                ;;
            Darwin)
                build_macos
                ;;
        esac
        ;;
    auto)
        build_wheel
        case "$(uname -s)" in
            Linux)
                if command -v dpkg-deb &>/dev/null; then
                    build_deb
                elif command -v rpmbuild &>/dev/null; then
                    build_rpm
                elif command -v makepkg &>/dev/null; then
                    build_arch
                fi
                ;;
            Darwin)
                build_macos
                ;;
        esac
        ;;
    *)
        echo "Usage: $0 {deb|rpm|arch|appimage|macos|wheel|all|auto}"
        exit 1
        ;;
esac

log "Done! Packages in $DIST_DIR/"
ls -lh "$DIST_DIR/" 2>/dev/null || true

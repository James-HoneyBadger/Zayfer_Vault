#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
#  HB Zayfer — Application Launcher
#
#  Usage:
#    ./run.sh              Launch the desktop GUI (default)
#    ./run.sh gui          Launch the desktop GUI
#    ./run.sh web          Launch the web server
#    ./run.sh web -p 9000  Launch the web server on port 9000
#    ./run.sh cli [ARGS]   Run a CLI command
#    ./run.sh build        Rebuild the native extension only
#    ./run.sh test         Run the full test suite
#    ./run.sh -h|--help    Show this help message
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
PYTHON="${VENV_DIR}/bin/python"
MATURIN_MANIFEST="crates/python/Cargo.toml"

# ── Colours ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[  OK]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERR ]${NC}  %s\n" "$*" >&2; }

# ── 1. Check Rust toolchain ─────────────────────────────────────────
check_rust() {
    if ! command -v cargo &>/dev/null; then
        err "Rust toolchain not found."
        err "Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    ok "Rust $(rustc --version | awk '{print $2}')"
}

# ── 2. Create / activate virtual environment ─────────────────────────
ensure_venv() {
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating Python virtual environment…"
        python3 -m venv "$VENV_DIR"
        ok "Virtual environment created at $VENV_DIR"
    fi
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    ok "Python $(python --version 2>&1 | awk '{print $2}') (venv active)"
}

# ── 3. Install Python dependencies if missing ────────────────────────
ensure_deps() {
    local missing=0
    python -c "import maturin" 2>/dev/null || missing=1
    if [[ $missing -eq 1 ]]; then
        info "Installing maturin…"
        pip install --quiet maturin
    fi

    # Check core optional deps based on mode
    case "${1:-gui}" in
        gui)
            python -c "import PySide6" 2>/dev/null || {
                info "Installing GUI dependencies…"
                pip install --quiet -e ".[gui]"
            }
            ;;
        web)
            python -c "import fastapi" 2>/dev/null || {
                info "Installing web dependencies…"
                pip install --quiet -e ".[web]"
            }
            ;;
        cli)
            python -c "import click" 2>/dev/null || {
                info "Installing CLI dependencies…"
                pip install --quiet -e ".[cli]"
            }
            ;;
        test)
            python -c "import pytest" 2>/dev/null || {
                info "Installing dev dependencies…"
                pip install --quiet -e ".[all]"
            }
            ;;
    esac
    ok "Python dependencies satisfied"
}

# ── 4. Build native extension if needed ──────────────────────────────
ensure_native() {
    # Rebuild if the shared library is missing or any Rust source is newer
    local so_path
    so_path=$(find "$VENV_DIR" -name "_native*.so" -o -name "_native*.pyd" 2>/dev/null | head -1)

    local need_build=0
    if [[ -z "$so_path" ]]; then
        need_build=1
    else
        # Check if any Rust source file is newer than the .so
        local newest_rs
        newest_rs=$(find "$PROJECT_DIR/crates" -name '*.rs' -newer "$so_path" 2>/dev/null | head -1)
        [[ -n "$newest_rs" ]] && need_build=1
    fi

    if [[ $need_build -eq 1 ]]; then
        info "Building native extension (this may take a minute)…"
        maturin develop --release -m "$MATURIN_MANIFEST"
        ok "Native extension built"
    else
        ok "Native extension up to date"
    fi
}

# ── 5. Launch ────────────────────────────────────────────────────────
main() {
    cd "$PROJECT_DIR"
    local mode="${1:-gui}"

    # Handle help flags
    case "$mode" in
        -h|--help|help)
            echo "HB Zayfer v1.0.0 — Encryption/Decryption Suite"
            echo ""
            echo "Usage: $0 [MODE] [OPTIONS]"
            echo ""
            echo "Modes:"
            echo "  gui           Launch the desktop GUI (default)"
            echo "  web [OPTS]    Launch the web server (--host, --port/-p)"
            echo "  cli [ARGS]    Run a CLI command"
            echo "  build         Rebuild the native extension only"
            echo "  test          Run the full test suite"
            echo "  -h, --help    Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                   # Launch GUI"
            echo "  $0 web -p 9000       # Web server on port 9000"
            echo "  $0 cli encrypt -i secret.txt -o secret.hbzf"
            echo "  $0 test              # Run all tests"
            exit 0
            ;;
    esac

    printf "\n${BOLD}  ╔══════════════════════════════════════╗${NC}\n"
    printf "${BOLD}  ║     🔐  HB Zayfer  v1.0.0  🔐      ║${NC}\n"
    printf "${BOLD}  ╚══════════════════════════════════════╝${NC}\n\n"

    check_rust
    ensure_venv
    ensure_deps "$mode"
    ensure_native

    printf "\n"

    case "$mode" in
        gui)
            info "Launching desktop GUI…"
            exec python -m hb_zayfer.gui
            ;;
        web)
            shift
            info "Starting web server…"
            exec python -m hb_zayfer.web "$@"
            ;;
        cli)
            shift
            exec python -m hb_zayfer.cli "$@"
            ;;
        build)
            ok "Build complete — native extension is ready."
            ;;
        test)
            info "Running Rust tests…"
            cargo test --workspace
            printf "\n"
            info "Running Python tests…"
            pytest tests/python/ -v
            ;;
        *)
            err "Unknown mode: $mode"
            echo "Usage: $0 [gui|web|cli|build|test]"
            exit 1
            ;;
    esac
}

main "$@"

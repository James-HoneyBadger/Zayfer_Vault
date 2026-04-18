# Installation Guide

**Zayfer Vault v1.1.0**

Complete installation instructions for the current **Rust-first** Zayfer Vault workspace on Linux, macOS, and Windows.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Install (Recommended)](#quick-install-recommended)
- [Detailed Installation Steps](#detailed-installation-steps)
- [Platform-Specific Notes](#platform-specific-notes)
- [Troubleshooting](#troubleshooting)
- [Verifying Installation](#verifying-installation)
- [Maintenance and Updates](#maintenance-and-updates)

---

## System Requirements

### Minimum Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Arch, Fedora, etc.), macOS 10.15+, or Windows 10+
- **Rust**: 1.75 or later (stable toolchain)
- **Python**: 3.10 or later
- **Disk Space**: ~500 MB for dependencies and build artifacts
- **RAM**: 2 GB minimum, 4 GB recommended for compilation

### System Dependencies (Linux)

Install these packages using your system's package manager:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev nettle-dev build-essential python3-venv libxcb-cursor0
```

> `libxcb-cursor0` is required for the PySide6 desktop GUI on many Linux setups.

**Arch Linux:**
```bash
sudo pacman -S pkg-config openssl nettle base-devel python
```

**Fedora:**
```bash
sudo dnf install pkg-config openssl-devel nettle-devel gcc python3-devel
```

**macOS:**
```bash
brew install pkg-config openssl nettle
```

**Windows:**
- Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
- Most dependencies are handled automatically by Rust/Cargo

---

## Quick Install (Recommended)

For most users, this one-command installation will set up everything:

### Linux/macOS / Windows (Git Bash, WSL, or a regular terminal)

```bash
# Clone the repository and let the launcher handle setup
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh              # Creates venv, installs deps, builds native extension, launches GUI
./run.sh web          # Start the web interface instead
./run.sh cli --help   # Show CLI help
```

### Manual Quick Install

```bash
# Navigate to project directory
cd /path/to/Zayfer_Vault

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate on Windows

# Install Python build tools and project extras
pip install --upgrade pip maturin
pip install -e ".[all]"

# Build and install the Rust extension
maturin develop --release -m crates/python/Cargo.toml

# Verify installation
python -c "import hb_zayfer; print(f'✓ Zayfer Vault {hb_zayfer.version()} installed successfully')"
```

---

## Quick Launch (Recommended)

The included `run.sh` script handles the entire setup automatically:

```bash
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh              # Creates venv, installs deps, builds native ext, launches GUI
./run.sh web          # Web server
./run.sh cli --help   # CLI commands
./run.sh build        # Build only (no launch)
./run.sh doctor       # Show environment diagnostics
./run.sh test         # Run full test suite
```

The script checks for Rust, creates/activates the venv, installs missing
Python packages, rebuilds the native extension when Rust sources change,
and launches the requested interface.

### Branding and Compatibility Note

The product is now called **Zayfer Vault**, but some internal identifiers still
use the original compatibility names:

- Python package: `hb_zayfer`
- Environment variables: `HB_ZAYFER_*`
- Native module: `hb_zayfer._native`

This is expected and helps preserve backward compatibility for scripts,
imports, and existing installations.

If you prefer manual setup, follow the steps below.

---

## Detailed Installation Steps

### Step 1: Install Rust Toolchain

Zayfer Vault's core cryptographic engine is written in Rust. Install it using rustup:

```bash
# Download and install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# The installer will prompt you - accept defaults by pressing Enter
# Or use -y flag for non-interactive installation

# Load Rust environment variables
source "$HOME/.cargo/env"

# Verify Rust installation
cargo --version  # Should show: cargo 1.XX.X
rustc --version  # Should show: rustc 1.XX.X
```

**Alternative: Update existing Rust installation**
```bash
rustup update stable
rustup default stable
```

### Step 2: Clone Repository (if not already done)

```bash
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
```

### Step 3: Setup Python Virtual Environment

**Why use a virtual environment?**
- Isolates project dependencies from system Python
- Required on systems with PEP 668 externally-managed Python (Arch Linux, newer Ubuntu)
- Prevents version conflicts

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# OR
.venv\Scripts\activate     # Windows PowerShell
# OR
.venv\Scripts\activate.bat # Windows CMD
```

> **Note**: You need to activate the virtual environment every time you open a new terminal to work with Zayfer Vault.

### Step 4: Install Python Build Tools

```bash
# Upgrade pip to latest version
pip install --upgrade pip

# Install maturin (Rust-Python build bridge)
pip install maturin
```

### Step 5: Install Python Dependencies

Choose the feature set you need:

**Option A: Install everything (recommended for development)**
```bash
pip install -e ".[all]"
```

**Option B: Install specific Python extras**
```bash
# GUI compatibility shell
pip install -e ".[gui]"

# Python packaging / compatibility CLI helpers
pip install -e ".[cli]"

# Python compatibility web backend
pip install -e ".[web]"

# Development tools (pytest, httpx)
pip install -e ".[dev]"

# Combine multiple extras
pip install -e ".[gui,cli,web]"
```

> The primary supported CLI and web runtime paths are still `./run.sh cli ...` and `./run.sh web`, both routed through Rust.

**Option C: Manual dependency installation**
```bash
pip install PySide6      # Desktop GUI framework
pip install click rich   # CLI framework and formatting
pip install fastapi uvicorn python-multipart  # Web framework
pip install pytest pytest-asyncio httpx       # Testing tools
```

### Step 6: Build the Native Rust Extension

This compiles the Rust cryptographic core and makes it available to Python:

```bash
# Development build (recommended - fast compilation, editable install)
maturin develop --release -m crates/python/Cargo.toml

# Production build (creates a distributable wheel)
maturin build --release -m crates/python/Cargo.toml
```

> **Build Time**: First build takes 5-15 minutes depending on your CPU. Subsequent builds are much faster.

**Build Flags Explained:**
- `--release`: Optimized build with better performance
- `-m crates/python/Cargo.toml`: Specifies the Python extension manifest

### Step 7: Verify Installation

```bash
# Test Python module import
python -c "import hb_zayfer; print(f'Version: {hb_zayfer.version()}')"

# Test CLI is available
./run.sh cli --help

# Test GUI launches (if installed)
./run.sh gui

# Test web server (if installed)
./run.sh web
```

### Step 8: Build WASM Module (Optional)

If you want to use Zayfer Vault in the browser or Node.js:

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build WASM module
./scripts/build-wasm.sh

# Output: pkg/ directory with .wasm + JS bindings
```

The WASM module provides AES-GCM, ChaCha20, Ed25519, X25519, Argon2id KDF,
SHA-256, and secure random bytes for browser/Node.js use.

---

## Platform-Specific Notes

### Linux

**Externally-Managed Python (PEP 668)**

If you see this error:
```
error: externally-managed-environment
```

You **must** use a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Display Server Requirements (GUI)**

The GUI requires a running X11 or Wayland display server. For headless systems:
```bash
# Install virtual display
sudo apt-get install xvfb

# Run GUI with virtual display
xvfb-run python -m hb_zayfer.gui.app
```

**DBus Warnings**

You may see warnings like:
```
qt.qpa.theme.gnome: dbus reply error
```
These are non-critical and don't affect functionality.

### macOS

**M1/M2 Apple Silicon**

No special configuration needed - builds natively for ARM64.

**OpenSSL Issues**

If you encounter OpenSSL linking errors:
```bash
brew install openssl@3
export OPENSSL_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
```

### Windows

**Visual Studio Build Tools**

Download and install from: https://visualstudio.microsoft.com/downloads/

Select "Desktop development with C++" workload.

**PowerShell Execution Policy**

If activation fails, run PowerShell as Administrator:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Path Length Limit**

Enable long paths if you encounter path-related errors:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

---

## Troubleshooting

### Build Failures

**Problem**: `error: linker 'cc' not found`
```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# Arch
sudo pacman -S base-devel

# macOS
xcode-select --install
```

**Problem**: `error: failed to run custom build command for openssl-sys`
```bash
# Install OpenSSL development headers
sudo apt-get install libssl-dev  # Ubuntu/Debian
sudo pacman -S openssl           # Arch
brew install openssl             # macOS
```

**Problem**: Maturin build fails with "No such file or directory"
```bash
# Ensure you're specifying the correct manifest path
maturin develop --release -m crates/python/Cargo.toml
```

### Runtime Issues

**Problem**: `ModuleNotFoundError: No module named 'hb_zayfer'`

Solution:
1. Ensure virtual environment is activated: `source .venv/bin/activate`
2. Rebuild the module: `maturin develop --release -m crates/python/Cargo.toml`
3. Check PYTHONPATH is not interfering

**Problem**: `ImportError: dynamic module does not define module export function`

Solution:
This indicates a Python version mismatch. Rebuild with the correct Python:
```bash
maturin develop --release -m crates/python/Cargo.toml -i python3.11
```

**Problem**: GUI doesn't launch

Solution:
```bash
# Verify PySide6 is installed
pip list | grep PySide6

# Reinstall if missing
pip install --force-reinstall PySide6

# Install the common Linux Qt/XCB dependency if needed
sudo apt-get install -y libxcb-cursor0

# Check for display server (Linux)
echo $DISPLAY  # Should show something like ":0"
```

### Permission Issues

**Problem**: `Permission denied` when installing packages

Solution (Linux/macOS):
```bash
# Never use sudo with pip in a venv!
# Instead, recreate the venv:
deactivate
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
```

---

## Verifying Installation

Run the full test suite to ensure everything works:

```bash
# Activate environment
source .venv/bin/activate

# Run Rust tests
cargo test --workspace

# Run Python tests
pip install -e ".[dev]"
pytest tests/

# Test individual components
python -c "
import hb_zayfer as hbz
print(f'✓ Core module: v{hbz.version()}')

# Test basic crypto operations
plaintext = b'Hello, World!'
password = b'test123'

# Encrypt
encrypted = hbz.encrypt_data(plaintext, 'aes', 'password', password)
print(f'✓ Encryption: {len(encrypted)} bytes')

# Decrypt
decrypted = hbz.decrypt_data(encrypted, password)
assert decrypted == plaintext
print('✓ Decryption: matches original')

print('\\n✓✓✓ All verification checks passed!')
"
```

---

## Next Steps

After successful installation:

1. **Read the documentation**: Check `docs/` folder for detailed guides
   - `CLI.md` - Command-line interface usage
   - `PYTHON_API.md` - Python API reference
   - `WEB_GUI.md` - Desktop and web interface guides

2. **Try the examples**:
   ```bash
   # Generate your first key pair
   hb-zayfer keygen --algorithm ed25519 --label my-key
   
   # Encrypt a file
   echo "Secret message" > test.txt
   hb-zayfer encrypt --input test.txt --output test.hbzf --password
   
   # Generate a secure password
   hb-zayfer passgen --length 24
   
   # Launch the GUI
   python -m hb_zayfer.gui.app
   ```

3. **Join the community**: Report issues or contribute at https://github.com/James-HoneyBadger/Zayfer_Vault

---

## Maintenance and Updates

Use the following procedure whenever you update the repository, switch Python versions, or suspect a broken local build:

```bash
# Update toolchains
rustup update stable
source .venv/bin/activate
pip install --upgrade pip maturin

# Pull latest project changes
git pull origin main

# Refresh dependencies and rebuild the native extension
pip install -e ".[all]"
maturin develop --release -m crates/python/Cargo.toml

# Run the supported verification command
HB_ZAYFER_SKIP_ONBOARDING=1 QT_QPA_PLATFORM=offscreen ./run.sh test
```

Recommended maintenance habits:

- **Back up** the keystore after creating or importing important keys.
- Run `hb-zayfer audit verify` periodically to confirm log integrity.
- Use a password manager and rotate compromised passphrases immediately.
- Keep at least one **offline backup** of your `.hbzf-backup` archives.

For the full operational checklist, see [`docs/MAINTENANCE.md`](docs/MAINTENANCE.md).

---

## Uninstallation

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf .venv

# Remove Cargo build artifacts
cargo clean

# Remove keystore (CAUTION: This deletes your keys!)
rm -rf ~/.hb_zayfer/

# Uninstall Rust (optional)
rustup self uninstall
```

---

For additional help, see:
- GitHub Issues: https://github.com/James-HoneyBadger/Zayfer_Vault/issues
- Documentation: `docs/README.md`
- Security Policy: `docs/SECURITY.md`

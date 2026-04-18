# Maintenance Guide

Operational maintenance, upgrades, and recovery procedures for Zayfer Vault.

This document is intended for desktop users, administrators, and maintainers who want the application to remain **secure, recoverable, and up to date**.

---

## 1) Routine Maintenance Schedule

| Frequency | Task | Why it matters |
|---|---|---|
| After key changes | Create and verify a backup | Prevents unrecoverable key loss |
| Weekly | Review recent audit entries | Detects unexpected activity |
| Monthly | Update Rust/Python dependencies | Pulls in bug and security fixes |
| Quarterly | Test a restore on non-production data | Confirms backups are usable |
| On suspicion of compromise | Rotate passphrases and keys | Limits further exposure |

---

## 2) Core Health Checks

Run these commands from the project root:

```bash
# Activate the environment if needed
source .venv/bin/activate

# Rebuild native bindings if Rust code changed
maturin develop --release -m crates/python/Cargo.toml

# Verify the full project
HB_ZAYFER_SKIP_ONBOARDING=1 QT_QPA_PLATFORM=offscreen ./run.sh test
```

What to look for:

- test suite completes with **0 failures**,
- the native extension is reported as **up to date** or rebuilds successfully,
- CLI, GUI, and web startup remain functional.

### Quick diagnostics

If startup or dependency detection looks suspicious, run:

```bash
./run.sh doctor
```

This prints Python, Cargo, virtual environment, and native-extension status in
one place and is the fastest first check before deeper troubleshooting.

---

## 3) Backups and Recovery

### Create a backup

```bash
hb-zayfer backup create -o ~/backups/hbz-$(date +%Y%m%d).hbzf-backup
```

### Verify it immediately

```bash
hb-zayfer backup verify -i ~/backups/hbz-$(date +%Y%m%d).hbzf-backup
```

### Restore if needed

```bash
hb-zayfer backup restore -i ~/backups/hbz-$(date +%Y%m%d).hbzf-backup
```

### Recommended practice

- keep at least **3 generations** of backups,
- store one copy **offline**,
- use a backup passphrase that is **different** from daily key passphrases,
- test restore on a safe workstation before an emergency happens.

---

## 4) Updating the Project

### Git-based update

```bash
git pull origin main
source .venv/bin/activate
pip install --upgrade pip maturin
pip install -e ".[all]"
maturin develop --release -m crates/python/Cargo.toml
./run.sh build
```

### Rust toolchain update

```bash
rustup update stable
rustup default stable
```

### Why rebuild after updates?

Zayfer Vault uses a Rust core exposed to Python via PyO3. If:

- Python version changes,
- Rust dependencies change, or
- native code is modified,

then the extension should be rebuilt with `maturin develop --release -m crates/python/Cargo.toml`.

---

## 5) Auditing and Integrity Checks

### Inspect the audit trail

```bash
hb-zayfer audit show -n 50
hb-zayfer audit verify
```

If `audit verify` fails:

1. stop making further changes,
2. copy the keystore and audit log for investigation,
3. compare against your last known-good backup,
4. rotate keys and passphrases if compromise is suspected.

---

## 6) Key Rotation Guidance

Rotate keys when:

- a laptop, server, or removable drive is lost,
- a passphrase may have been exposed,
- a team member leaves,
- policy requires periodic rollover.

Suggested process:

1. generate a replacement key,
2. distribute the new public key,
3. update contact mappings,
4. archive or revoke the old key,
5. create and verify a fresh backup.

---

## 7) Environment Variables

| Variable | Purpose |
|---|---|
| `HB_ZAYFER_HOME` | Override the default keystore/config directory |
| `HB_ZAYFER_API_TOKEN` | Require bearer-token auth for the web API |
| `HB_ZAYFER_RATE_LIMIT` | Set the per-IP API request limit |
| `HB_ZAYFER_RATE_WINDOW` | Set the rate-limit time window in seconds |
| `HB_ZAYFER_PORT` | Default port for the web UI |
| `HB_ZAYFER_SKIP_ONBOARDING` | Skip the first-run prompt for headless testing/CI |

> **Compatibility note:** the environment-variable prefix remains `HB_ZAYFER_`
after the Zayfer Vault rebrand so existing automation continues to work.

---

## 8) Safe Cleanup

Use secure deletion only for temporary material you no longer need:

```bash
hb-zayfer shred sensitive.txt --passes 3
hb-zayfer shred ./temp-secrets --recursive
```

Notes:

- SSD wear-leveling and journaling filesystems can preserve remnants,
- shredding is best combined with **full-disk encryption**,
- do **not** shred your only copy of a key or backup.

---

## 9) If Something Goes Wrong

### GUI will not open

```bash
./run.sh build
./run.sh
```

### Python module import fails

```bash
source .venv/bin/activate
maturin develop --release -m crates/python/Cargo.toml
python -c "import hb_zayfer; print(hb_zayfer.version())"
```

### Web API should require auth

```bash
export HB_ZAYFER_API_TOKEN="change-me"
./run.sh web
```

Then call the API with:

```http
Authorization: Bearer change-me
```

---

## 10) Maintenance Checklist

Use this checklist for regular operations:

- [ ] Backups created and verified
- [ ] Audit chain verifies successfully
- [ ] Test suite passes after upgrades
- [ ] Public keys shared through verified channels
- [ ] Old or compromised keys rotated out
- [ ] Password manager entries updated
- [ ] Offline recovery copy still accessible

---

## Related Documentation

- [`../../INSTALL.md`](../../INSTALL.md)
- [`USER_GUIDE.md`](USER_GUIDE.md)
- [`TECHNICAL_REFERENCE.md`](../reference/TECHNICAL_REFERENCE.md)
- [`TUTORIAL_ENCRYPTION_PASSWORDS.md`](TUTORIAL_ENCRYPTION_PASSWORDS.md)

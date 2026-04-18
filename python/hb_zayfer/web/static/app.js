/* ==========================================================================
   Zayfer Vault – Web UI Application Logic (Vanilla JS)
   ========================================================================== */

const API = "/api";

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function show(el) { if (el) el.classList.remove("hidden"); }
function hide(el) { if (el) el.classList.add("hidden"); }

function toast(msg, durationMs = 3000) {
    const t = $("#toast");
    if (!t) return;
    t.textContent = msg;
    show(t);
    clearTimeout(toast._tid);
    toast._tid = setTimeout(() => hide(t), durationMs);
}

function b64Encode(str) {
    return btoa(new TextEncoder().encode(str).reduce((s, b) => s + String.fromCharCode(b), ""));
}

function resultBox(el, ok, msg) {
    if (!el) return;
    el.textContent = msg;
    el.className = `result-box ${ok ? "success" : "error"}`;
    show(el);
}

function esc(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
}

function truncFp(fp) {
    return fp && fp.length > 16 ? fp.slice(0, 8) + "…" + fp.slice(-8) : fp;
}

function authHeaders() {
    const headers = {};
    const token = document.querySelector('meta[name="api-token"]')?.content || window.__HB_API_TOKEN;
    if (token) headers["Authorization"] = `Bearer ${token}`;
    return headers;
}

async function api(method, path, body) {
    const headers = authHeaders();
    const opts = { method, headers };
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
    }

    const res = await fetch(`${API}${path}`, opts);
    const contentType = res.headers.get("content-type") || "";
    const data = contentType.includes("application/json") ? await res.json() : await res.text();
    if (!res.ok) {
        throw new Error((data && data.detail) || `API error ${res.status}`);
    }
    return data;
}

async function apiUpload(path, file, params = {}) {
    const query = new URLSearchParams(params).toString();
    const form = new FormData();
    form.append("file", file);

    const res = await fetch(`${API}${path}${query ? `?${query}` : ""}`, {
        method: "POST",
        headers: authHeaders(),
        body: form,
    });

    if (!res.ok) {
        let msg = `API error ${res.status}`;
        try {
            const data = await res.json();
            msg = data.detail || msg;
        } catch {
            try { msg = await res.text() || msg; } catch { /* ignore */ }
        }
        throw new Error(msg);
    }
    return res;
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function downloadNameFromResponse(res, fallback) {
    const contentDisposition = res.headers.get("Content-Disposition") || "";
    const match = contentDisposition.match(/filename="([^"]+)"/i);
    return match?.[1] || fallback;
}

function setActivePage(page) {
    $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
    $$(".page").forEach((p) => p.classList.remove("active"));
    const pageEl = $(`#page-${page}`);
    if (pageEl) pageEl.classList.add("active");

    if (page === "home") refreshOverview();
    if (page === "keyring") refreshKeys();
    if (page === "contacts") refreshContacts();
    if (page === "audit") refreshAudit();
    if (page === "settings") loadConfigForm();
}

async function refreshOverview() {
    try {
        const [version, keys, contacts, audit] = await Promise.all([
            api("GET", "/version"),
            api("GET", "/keys"),
            api("GET", "/contacts"),
            api("GET", "/audit/count"),
        ]);
        $("#version-label").textContent = `v${version.version}`;
        $("#home-version").textContent = version.version;
        $("#home-keys").textContent = keys.length;
        $("#home-contacts").textContent = contacts.length;
        $("#home-audit").textContent = audit.count;
    } catch (e) {
        toast(`Failed to load overview: ${e.message}`);
    }
}

async function refreshKeys() {
    const tbody = $("#keys-table tbody");
    const empty = $("#keys-empty");
    if (!tbody) return;
    tbody.innerHTML = "";
    hide(empty);

    try {
        const keys = await api("GET", "/keys");
        if (keys.length === 0) return show(empty);
        for (const k of keys) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td title="${esc(k.fingerprint)}">${esc(truncFp(k.fingerprint))}</td>
                <td>${esc(k.algorithm)}</td>
                <td>${esc(k.label)}</td>
                <td>${esc(k.created_at.slice(0, 10))}</td>
                <td>${k.has_private ? "✓" : "—"}</td>
                <td>${k.has_public ? "✓" : "—"}</td>
                <td><button class="btn-danger btn-del-key" data-fp="${esc(k.fingerprint)}">Delete</button></td>`;
            tbody.appendChild(tr);
        }
        tbody.querySelectorAll(".btn-del-key").forEach((btn) => {
            btn.addEventListener("click", async () => {
                if (!confirm(`Delete key ${truncFp(btn.dataset.fp)}?`)) return;
                try {
                    await api("DELETE", `/keys/${encodeURIComponent(btn.dataset.fp)}`);
                    toast("Key deleted.");
                    refreshKeys();
                    refreshOverview();
                } catch (e) {
                    toast(`Delete failed: ${e.message}`);
                }
            });
        });
    } catch (e) {
        toast(`Failed to load keys: ${e.message}`);
    }
}

async function refreshContacts() {
    const tbody = $("#contacts-table tbody");
    const empty = $("#contacts-empty");
    if (!tbody) return;
    tbody.innerHTML = "";
    hide(empty);

    try {
        const contacts = await api("GET", "/contacts");
        if (contacts.length === 0) return show(empty);
        for (const c of contacts) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${esc(c.name)}</td>
                <td>${esc(c.email || "—")}</td>
                <td>${c.key_fingerprints.map(truncFp).map(esc).join(", ") || "—"}</td>
                <td>${esc(c.created_at.slice(0, 10))}</td>
                <td><button class="btn-danger btn-del-ct" data-name="${esc(c.name)}">Remove</button></td>`;
            tbody.appendChild(tr);
        }
        tbody.querySelectorAll(".btn-del-ct").forEach((btn) => {
            btn.addEventListener("click", async () => {
                if (!confirm(`Remove contact "${btn.dataset.name}"?`)) return;
                try {
                    await api("DELETE", `/contacts/${encodeURIComponent(btn.dataset.name)}`);
                    toast("Contact removed.");
                    refreshContacts();
                    refreshOverview();
                } catch (e) {
                    toast(`Remove failed: ${e.message}`);
                }
            });
        });
    } catch (e) {
        toast(`Failed to load contacts: ${e.message}`);
    }
}

async function refreshAudit() {
    const tbody = $("#audit-table tbody");
    const empty = $("#audit-empty");
    if (!tbody) return;
    tbody.innerHTML = "";
    hide(empty);

    try {
        const [entries, count] = await Promise.all([
            api("GET", "/audit/recent?limit=20"),
            api("GET", "/audit/count"),
        ]);
        $("#audit-count-label").textContent = count.count;
        if (entries.length === 0) return show(empty);

        for (const entry of entries) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${esc((entry.timestamp || "").replace("T", " ").slice(0, 19))}</td>
                <td>${esc(entry.operation || "—")}</td>
                <td>${esc(entry.note || "—")}</td>`;
            tbody.appendChild(tr);
        }
    } catch (e) {
        toast(`Failed to load audit log: ${e.message}`);
    }
}

async function loadConfigForm() {
    try {
        const cfg = await api("GET", "/config");
        if ($("#cfg-cipher")) $("#cfg-cipher").value = cfg.cipher || "AES-256-GCM";
        if ($("#cfg-kdf")) $("#cfg-kdf").value = cfg.kdf || "Argon2id";
        if ($("#cfg-clipboard")) $("#cfg-clipboard").value = cfg.clipboard_auto_clear ?? 30;
    } catch (e) {
        toast(`Failed to load settings: ${e.message}`);
    }
}

function updatePassgenMode() {
    const mode = $("#pg-mode")?.value || "password";
    if (mode === "passphrase") {
        show($("#pg-words-wrap"));
        hide($("#pg-length-wrap"));
    } else {
        hide($("#pg-words-wrap"));
        show($("#pg-length-wrap"));
    }
}

function initNavigation() {
    $$(".nav-btn").forEach((btn) => btn.addEventListener("click", () => setActivePage(btn.dataset.page)));
    $$(".quick-nav").forEach((btn) => btn.addEventListener("click", () => setActivePage(btn.dataset.nav)));
}

function initActions() {
    $("#kg-algo")?.addEventListener("change", () => {
        const wrap = $("#kg-uid-wrap");
        if ($("#kg-algo").value === "pgp") show(wrap); else hide(wrap);
    });

    $("#btn-encrypt")?.addEventListener("click", async () => {
        const algo = $("#enc-algo").value;
        const pw = $("#enc-passphrase").value;
        const pt = $("#enc-plaintext").value;
        if (!pw || !pt) return toast("Passphrase and plaintext are required.");
        try {
            const res = await api("POST", "/encrypt/text", { plaintext: pt, passphrase: pw, algorithm: algo });
            $("#enc-output").value = res.ciphertext_b64;
            toast("Text encrypted.");
        } catch (e) {
            toast(`Encryption failed: ${e.message}`);
        }
    });

    $("#btn-encrypt-file")?.addEventListener("click", async () => {
        const file = $("#enc-file-input").files[0];
        const pw = $("#enc-file-passphrase").value;
        const algo = $("#enc-file-algo").value;
        if (!file || !pw) return toast("Choose a file and enter a passphrase.");
        try {
            const res = await apiUpload("/encrypt/file", file, { passphrase: pw, algorithm: algo });
            const blob = await res.blob();
            downloadBlob(blob, downloadNameFromResponse(res, `${file.name}.hbzf`));
            toast("File encrypted and downloaded.");
        } catch (e) {
            toast(`File encryption failed: ${e.message}`);
        }
    });

    $("#btn-decrypt")?.addEventListener("click", async () => {
        const pw = $("#dec-passphrase").value;
        const ct = $("#dec-ciphertext").value;
        if (!pw || !ct) return toast("Passphrase and ciphertext are required.");
        try {
            const res = await api("POST", "/decrypt/text", { ciphertext_b64: ct, passphrase: pw });
            $("#dec-output").value = res.plaintext;
            toast("Text decrypted.");
        } catch (e) {
            toast(`Decryption failed: ${e.message}`);
        }
    });

    $("#btn-decrypt-file")?.addEventListener("click", async () => {
        const file = $("#dec-file-input").files[0];
        const pw = $("#dec-file-passphrase").value;
        if (!file || !pw) return toast("Choose a file and enter the passphrase.");
        try {
            const res = await apiUpload("/decrypt/file", file, { passphrase: pw });
            const blob = await res.blob();
            downloadBlob(blob, downloadNameFromResponse(res, file.name.replace(/\.hbzf$/i, "") || `${file.name}.dec`));
            toast("File decrypted and downloaded.");
        } catch (e) {
            toast(`File decryption failed: ${e.message}`);
        }
    });

    $("#btn-keygen")?.addEventListener("click", async () => {
        const algo = $("#kg-algo").value;
        const label = $("#kg-label").value.trim();
        const pw = $("#kg-pass").value;
        const pw2 = $("#kg-pass2").value;
        const uid = $("#kg-uid").value.trim();
        if (!label) return toast("Label is required.");
        if (!pw) return toast("Passphrase is required.");
        if (pw !== pw2) return toast("Passphrases do not match.");

        const resultEl = $("#kg-result");
        hide(resultEl);
        try {
            const body = { algorithm: algo, label, passphrase: pw };
            if (algo === "pgp" && uid) body.user_id = uid;
            const res = await api("POST", "/keygen", body);
            resultBox(resultEl, true, `✓ Key generated\nAlgorithm: ${res.algorithm}\nLabel: ${res.label}\nFingerprint: ${res.fingerprint}`);
            toast("Key generated successfully.");
            refreshKeys();
            refreshOverview();
        } catch (e) {
            resultBox(resultEl, false, `✗ ${e.message}`);
        }
    });

    $("#btn-refresh-keys")?.addEventListener("click", refreshKeys);
    $("#btn-refresh-contacts")?.addEventListener("click", refreshContacts);

    $("#btn-add-contact")?.addEventListener("click", async () => {
        const name = $("#ct-name").value.trim();
        const email = $("#ct-email").value.trim() || null;
        if (!name) return toast("Name is required.");
        try {
            await api("POST", "/contacts", { name, email });
            toast(`Contact "${name}" added.`);
            $("#ct-name").value = "";
            $("#ct-email").value = "";
            refreshContacts();
            refreshOverview();
        } catch (e) {
            toast(`Add contact failed: ${e.message}`);
        }
    });

    $("#btn-sign")?.addEventListener("click", async () => {
        const algo = $("#sig-algo").value;
        const fp = $("#sig-fp").value.trim();
        const pw = $("#sig-pass").value;
        const msg = $("#sig-msg").value;
        if (!fp || !pw || !msg) return toast("Fingerprint, passphrase, and message are required.");
        try {
            const res = await api("POST", "/sign", {
                message_b64: b64Encode(msg),
                fingerprint: fp,
                passphrase: pw,
                algorithm: algo,
            });
            $("#sig-out").value = res.signature_b64;
            toast("Message signed.");
        } catch (e) {
            toast(`Signing failed: ${e.message}`);
        }
    });

    $("#btn-verify")?.addEventListener("click", async () => {
        const algo = $("#ver-algo").value;
        const fp = $("#ver-fp").value.trim();
        const msg = $("#ver-msg").value;
        const sig = $("#ver-sig").value.trim();
        if (!fp || !msg || !sig) return toast("Fingerprint, message, and signature are required.");

        const resultEl = $("#ver-result");
        hide(resultEl);
        try {
            const res = await api("POST", "/verify", {
                message_b64: b64Encode(msg),
                signature_b64: sig,
                fingerprint: fp,
                algorithm: algo,
            });
            resultBox(resultEl, !!res.valid, res.valid ? "✓ Signature is VALID" : "✗ Signature is INVALID");
        } catch (e) {
            resultBox(resultEl, false, `✗ ${e.message}`);
        }
    });

    $("#pg-mode")?.addEventListener("change", updatePassgenMode);
    $("#btn-passgen")?.addEventListener("click", async () => {
        const mode = $("#pg-mode").value;
        const body = mode === "passphrase"
            ? { words: Number($("#pg-words").value), separator: $("#pg-separator").value || "-" }
            : { length: Number($("#pg-length").value), exclude: $("#pg-exclude").value || "" };
        try {
            const res = await api("POST", "/passgen", body);
            $("#pg-output").value = res.value;
            $("#pg-meta").textContent = `${res.type} • approx. ${Math.round(res.entropy_bits)} bits of entropy`;
            toast("Credential generated.");
        } catch (e) {
            toast(`Generation failed: ${e.message}`);
        }
    });

    $("#btn-refresh-audit")?.addEventListener("click", refreshAudit);
    $("#btn-verify-audit")?.addEventListener("click", async () => {
        const resultEl = $("#audit-verify-result");
        hide(resultEl);
        try {
            const res = await api("GET", "/audit/verify");
            resultBox(resultEl, !!res.valid, res.valid ? "✓ Audit log integrity verified" : "✗ Audit log verification failed");
        } catch (e) {
            resultBox(resultEl, false, `✗ ${e.message}`);
        }
    });

    async function handleBackup(action) {
        const path = $("#bk-path").value.trim();
        const passphrase = $("#bk-pass").value;
        const label = $("#bk-label").value.trim() || null;
        const resultEl = $("#bk-result");
        hide(resultEl);

        if (!path) return toast("Backup path is required.");
        if (!passphrase) return toast("Backup passphrase is required.");

        try {
            const payload = action === "create"
                ? { output_path: path, passphrase, label }
                : { backup_path: path, passphrase };
            const endpoint = action === "create" ? "/backup/create" : action === "verify" ? "/backup/verify" : "/backup/restore";
            const res = await api("POST", endpoint, payload);
            resultBox(resultEl, true, `✓ Backup ${action} complete\nCreated: ${res.created_at}\nKeys: ${res.private_key_count} private / ${res.public_key_count} public\nContacts: ${res.contact_count}`);
            toast(`Backup ${action} complete.`);
            refreshOverview();
        } catch (e) {
            resultBox(resultEl, false, `✗ ${e.message}`);
        }
    }

    $("#btn-backup-create")?.addEventListener("click", () => handleBackup("create"));
    $("#btn-backup-verify")?.addEventListener("click", () => handleBackup("verify"));
    $("#btn-backup-restore")?.addEventListener("click", () => handleBackup("restore"));

    $("#btn-save-settings")?.addEventListener("click", async () => {
        const cipher = $("#cfg-cipher").value;
        const kdf = $("#cfg-kdf").value;
        const clipboard = Number($("#cfg-clipboard").value);
        const resultEl = $("#cfg-result");
        hide(resultEl);
        try {
            await Promise.all([
                api("PUT", "/config/cipher", { value: cipher }),
                api("PUT", "/config/kdf", { value: kdf }),
                api("PUT", "/config/clipboard_auto_clear", { value: clipboard }),
            ]);
            resultBox(resultEl, true, "✓ Settings saved");
            toast("Settings updated.");
        } catch (e) {
            resultBox(resultEl, false, `✗ ${e.message}`);
        }
    });

    $$(".btn-copy").forEach((btn) => {
        btn.addEventListener("click", () => {
            const target = $(`#${btn.dataset.target}`);
            const text = target?.value || target?.textContent || "";
            if (!text) return toast("Nothing to copy.");
            navigator.clipboard.writeText(text)
                .then(() => toast("Copied to clipboard."))
                .catch(() => {
                    target.select?.();
                    document.execCommand("copy");
                    toast("Copied.");
                });
        });
    });
}

(function init() {
    initNavigation();
    initActions();
    updatePassgenMode();
    setActivePage("home");
})();

"""HB_Zayfer CLI — Click-based command-line interface.

Entry point: ``hb-zayfer`` (installed via pip).
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

import hb_zayfer as hbz

console = Console()
err_console = Console(stderr=True, style="bold red")


def _prompt_passphrase(confirm: bool = False) -> bytes:
    """Prompt for a passphrase securely."""
    pw = getpass.getpass("Passphrase: ")
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            err_console.print("Passphrases do not match.")
            sys.exit(1)
    return pw.encode("utf-8")


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=hbz.version(), prog_name="hb-zayfer")
def cli() -> None:
    """HB_Zayfer — Encryption / Decryption Suite."""


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("algorithm", type=click.Choice(["rsa2048", "rsa4096", "ed25519", "x25519", "pgp"]))
@click.option("--label", "-l", required=True, help="Human-readable label for the key.")
@click.option("--user-id", "-u", default=None, help="User ID for PGP keys (e.g. 'Name <email>').")
@click.option("--export-dir", "-o", type=click.Path(), default=None, help="Directory to export public key.")
def keygen(algorithm: str, label: str, user_id: Optional[str], export_dir: Optional[str]) -> None:
    """Generate a new key pair and store it in the keyring."""
    passphrase = _prompt_passphrase(confirm=True)
    ks = hbz.KeyStore()

    with console.status(f"Generating {algorithm} key pair..."):
        if algorithm in ("rsa2048", "rsa4096"):
            bits = 2048 if algorithm == "rsa2048" else 4096
            priv_pem, pub_pem = hbz.rsa_generate(bits)
            fp = hbz.rsa_fingerprint(pub_pem)
            ks.store_private_key(fp, priv_pem.encode(), passphrase, algorithm, label)
            ks.store_public_key(fp, pub_pem.encode(), algorithm, label)
        elif algorithm == "ed25519":
            sk_pem, vk_pem = hbz.ed25519_generate()
            fp = hbz.ed25519_fingerprint(vk_pem)
            ks.store_private_key(fp, sk_pem.encode(), passphrase, algorithm, label)
            ks.store_public_key(fp, vk_pem.encode(), algorithm, label)
        elif algorithm == "x25519":
            sk_raw, pk_raw = hbz.x25519_generate()
            fp = hbz.x25519_fingerprint(pk_raw)
            ks.store_private_key(fp, sk_raw, passphrase, algorithm, label)
            ks.store_public_key(fp, pk_raw, algorithm, label)
        elif algorithm == "pgp":
            uid = user_id or label
            pub_arm, sec_arm = hbz.pgp_generate(uid)
            fp = hbz.pgp_fingerprint(pub_arm)
            ks.store_private_key(fp, sec_arm.encode(), passphrase, algorithm, label)
            ks.store_public_key(fp, pub_arm.encode(), algorithm, label)

    console.print(f"[green]Key generated:[/green] {label}")
    console.print(f"  Fingerprint: {fp}")
    console.print(f"  Algorithm:   {algorithm.upper()}")

    if export_dir:
        out = Path(export_dir) / f"{fp[:16]}.pub"
        pub_data = ks.load_public_key(fp)
        out.write_bytes(pub_data)
        console.print(f"  Public key exported to: {out}")


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (default: <input>.hbzf).")
@click.option("--algorithm", "-a", type=click.Choice(["aes", "chacha"]), default="aes", help="Symmetric cipher.")
@click.option("--password", "-p", is_flag=True, help="Encrypt with a passphrase.")
@click.option("--recipient", "-r", default=None, help="Recipient contact name or fingerprint prefix.")
def encrypt(input_file: str, output: Optional[str], algorithm: str, password: bool, recipient: Optional[str]) -> None:
    """Encrypt a file."""
    output = output or f"{input_file}.hbzf"

    if password or not recipient:
        pw = _prompt_passphrase(confirm=True)
        with console.status("Encrypting..."):
            hbz.encrypt_file(input_file, output, algorithm=algorithm, wrapping="password", passphrase=pw)
    else:
        ks = hbz.KeyStore()
        fps = ks.resolve_recipient(recipient)
        if not fps:
            err_console.print(f"No keys found for recipient '{recipient}'.")
            sys.exit(1)
        fp = fps[0]
        meta = ks.get_key_metadata(fp)
        if not meta:
            err_console.print(f"Key metadata not found for {fp}")
            sys.exit(1)
        pub_data = ks.load_public_key(fp)

        if meta.algorithm in ("RSA-2048", "RSA-4096"):
            with console.status("Encrypting with RSA..."):
                hbz.encrypt_file(input_file, output, algorithm=algorithm, wrapping="rsa",
                                 recipient_public_pem=pub_data.decode())
        elif meta.algorithm == "X25519":
            with console.status("Encrypting with X25519..."):
                hbz.encrypt_file(input_file, output, algorithm=algorithm, wrapping="x25519",
                                 recipient_public_raw=pub_data)
        else:
            err_console.print(f"Cannot encrypt with {meta.algorithm} key. Use RSA or X25519.")
            sys.exit(1)

    console.print(f"[green]Encrypted:[/green] {output}")


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (default: strip .hbzf).")
@click.option("--key", "-k", default=None, help="Fingerprint prefix of the decryption key.")
def decrypt(input_file: str, output: Optional[str], key: Optional[str]) -> None:
    """Decrypt an HBZF file."""
    if output is None:
        if input_file.endswith(".hbzf"):
            output = input_file[:-5]
        else:
            output = f"{input_file}.dec"

    # Read first bytes to check wrapping mode
    with open(input_file, "rb") as f:
        header_bytes = f.read(8)

    if len(header_bytes) < 8 or header_bytes[:4] != b"HBZF":
        err_console.print("Not a valid HBZF file.")
        sys.exit(1)

    wrapping_id = header_bytes[7]

    if wrapping_id == 0x00:  # Password
        pw = _prompt_passphrase()
        with console.status("Decrypting..."):
            hbz.decrypt_file(input_file, output, passphrase=pw)
    elif wrapping_id == 0x01:  # RSA
        ks = hbz.KeyStore()
        fp = _select_key(ks, key, "RSA")
        passphrase = _prompt_passphrase()
        priv_data = ks.load_private_key(fp, passphrase)
        with console.status("Decrypting with RSA..."):
            hbz.decrypt_file(input_file, output, private_pem=priv_data.decode())
    elif wrapping_id == 0x02:  # X25519
        ks = hbz.KeyStore()
        fp = _select_key(ks, key, "X25519")
        passphrase = _prompt_passphrase()
        priv_data = ks.load_private_key(fp, passphrase)
        with console.status("Decrypting with X25519..."):
            hbz.decrypt_file(input_file, output, secret_raw=priv_data)
    else:
        err_console.print(f"Unknown wrapping mode: 0x{wrapping_id:02x}")
        sys.exit(1)

    console.print(f"[green]Decrypted:[/green] {output}")


def _select_key(ks: hbz.KeyStore, hint: Optional[str], algo_prefix: str) -> str:
    """Resolve a key fingerprint from a hint or list matching private keys."""
    if hint:
        fps = ks.resolve_recipient(hint)
        if fps:
            return fps[0]
    # List keys with private part matching algo
    keys = [k for k in ks.list_keys() if k.has_private and k.algorithm.startswith(algo_prefix)]
    if not keys:
        err_console.print(f"No {algo_prefix} private keys found.")
        sys.exit(1)
    if len(keys) == 1:
        return keys[0].fingerprint
    # Multiple: show choices
    console.print(f"Multiple {algo_prefix} keys found:")
    for i, k in enumerate(keys, 1):
        console.print(f"  {i}. {k.label} ({k.fingerprint[:16]}..)")
    choice = click.prompt("Select key", type=int, default=1)
    return keys[choice - 1].fingerprint


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--key", "-k", default=None, help="Fingerprint prefix of signing key.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Signature output file (default: <input>.sig).")
@click.option("--algorithm", "-a", type=click.Choice(["ed25519", "rsa", "pgp"]), default="ed25519")
def sign(input_file: str, key: Optional[str], output: Optional[str], algorithm: str) -> None:
    """Sign a file."""
    output = output or f"{input_file}.sig"
    data = Path(input_file).read_bytes()
    ks = hbz.KeyStore()
    passphrase = _prompt_passphrase()

    if algorithm == "ed25519":
        fp = _select_key(ks, key, "Ed25519")
        priv_data = ks.load_private_key(fp, passphrase)
        sig = hbz.ed25519_sign(priv_data.decode(), data)
    elif algorithm == "rsa":
        fp = _select_key(ks, key, "RSA")
        priv_data = ks.load_private_key(fp, passphrase)
        sig = hbz.rsa_sign(priv_data.decode(), data)
    elif algorithm == "pgp":
        fp = _select_key(ks, key, "PGP")
        priv_data = ks.load_private_key(fp, passphrase)
        sig = hbz.pgp_sign(data, priv_data.decode())
    else:
        err_console.print(f"Unsupported signing algorithm: {algorithm}")
        sys.exit(1)

    Path(output).write_bytes(sig)
    console.print(f"[green]Signature written:[/green] {output}")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("signature_file", type=click.Path(exists=True))
@click.option("--key", "-k", default=None, help="Fingerprint prefix or contact name for verification key.")
@click.option("--algorithm", "-a", type=click.Choice(["ed25519", "rsa", "pgp"]), default="ed25519")
def verify(input_file: str, signature_file: str, key: Optional[str], algorithm: str) -> None:
    """Verify a file's signature."""
    data = Path(input_file).read_bytes()
    sig = Path(signature_file).read_bytes()
    ks = hbz.KeyStore()

    if not key:
        err_console.print("Please specify --key (fingerprint prefix or contact name).")
        sys.exit(1)

    fps = ks.resolve_recipient(key)
    if not fps:
        err_console.print(f"No keys found for '{key}'.")
        sys.exit(1)
    fp = fps[0]
    pub_data = ks.load_public_key(fp)

    if algorithm == "ed25519":
        valid = hbz.ed25519_verify(pub_data.decode(), data, sig)
    elif algorithm == "rsa":
        valid = hbz.rsa_verify(pub_data.decode(), data, sig)
    elif algorithm == "pgp":
        _, valid = hbz.pgp_verify(sig, pub_data.decode())
    else:
        err_console.print(f"Unsupported algorithm: {algorithm}")
        sys.exit(1)

    if valid:
        console.print("[green]Signature is VALID.[/green]")
    else:
        console.print("[red]Signature is INVALID.[/red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

@cli.group()
def keys() -> None:
    """Manage keys in the keyring."""


@keys.command("list")
def keys_list() -> None:
    """List all keys."""
    ks = hbz.KeyStore()
    all_keys = ks.list_keys()
    if not all_keys:
        console.print("No keys found.")
        return

    table = Table(title="Keyring")
    table.add_column("Label", style="cyan")
    table.add_column("Algorithm", style="green")
    table.add_column("Fingerprint")
    table.add_column("Private", justify="center")
    table.add_column("Public", justify="center")
    table.add_column("Created")

    for k in all_keys:
        table.add_row(
            k.label,
            k.algorithm,
            k.fingerprint[:24] + "..",
            "yes" if k.has_private else "no",
            "yes" if k.has_public else "no",
            k.created_at[:10],
        )

    console.print(table)


@keys.command("export")
@click.argument("fingerprint_prefix")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file.")
def keys_export(fingerprint_prefix: str, output: Optional[str]) -> None:
    """Export a public key."""
    ks = hbz.KeyStore()
    fps = ks.resolve_recipient(fingerprint_prefix)
    if not fps:
        err_console.print(f"No key found for '{fingerprint_prefix}'.")
        sys.exit(1)
    fp = fps[0]
    pub_data = ks.load_public_key(fp)
    if output:
        Path(output).write_bytes(pub_data)
        console.print(f"[green]Exported to:[/green] {output}")
    else:
        click.echo(pub_data.decode(errors="replace"))


@keys.command("import")
@click.argument("key_file", type=click.Path(exists=True))
@click.option("--label", "-l", required=True, help="Label for the imported key.")
@click.option("--algorithm", "-a", required=True, type=click.Choice(["rsa2048", "rsa4096", "ed25519", "x25519", "pgp"]))
@click.option("--private", is_flag=True, help="Import as a private key (will be encrypted).")
def keys_import(key_file: str, label: str, algorithm: str, private: bool) -> None:
    """Import a public or private key file."""
    data = Path(key_file).read_bytes()
    ks = hbz.KeyStore()
    fp = hbz.compute_fingerprint(data)

    if private:
        passphrase = _prompt_passphrase(confirm=True)
        ks.store_private_key(fp, data, passphrase, algorithm, label)
        console.print(f"[green]Private key imported:[/green] {fp[:24]}..")
    else:
        ks.store_public_key(fp, data, algorithm, label)
        console.print(f"[green]Public key imported:[/green] {fp[:24]}..")


@keys.command("delete")
@click.argument("fingerprint_prefix")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
def keys_delete(fingerprint_prefix: str, yes: bool) -> None:
    """Delete a key from the keyring."""
    ks = hbz.KeyStore()
    fps = ks.resolve_recipient(fingerprint_prefix)
    if not fps:
        err_console.print(f"No key found for '{fingerprint_prefix}'.")
        sys.exit(1)
    fp = fps[0]
    meta = ks.get_key_metadata(fp)
    if not meta:
        err_console.print("Key metadata not found.")
        sys.exit(1)
    if not yes:
        click.confirm(f"Delete '{meta.label}' ({fp[:16]}..) ?", abort=True)
    ks.delete_key(fp)
    console.print(f"[green]Deleted:[/green] {meta.label}")


# ---------------------------------------------------------------------------
# Contact management
# ---------------------------------------------------------------------------

@cli.group()
def contacts() -> None:
    """Manage contacts."""


@contacts.command("list")
def contacts_list() -> None:
    """List all contacts."""
    ks = hbz.KeyStore()
    all_contacts = ks.list_contacts()
    if not all_contacts:
        console.print("No contacts found.")
        return

    table = Table(title="Contacts")
    table.add_column("Name", style="cyan")
    table.add_column("Email")
    table.add_column("Keys", justify="right")
    table.add_column("Notes")

    for c in all_contacts:
        table.add_row(c.name, c.email or "", str(len(c.key_fingerprints)), c.notes or "")

    console.print(table)


@contacts.command("add")
@click.argument("name")
@click.option("--email", "-e", default=None, help="Contact email.")
@click.option("--notes", "-n", default=None, help="Notes.")
def contacts_add(name: str, email: Optional[str], notes: Optional[str]) -> None:
    """Add a new contact."""
    ks = hbz.KeyStore()
    ks.add_contact(name, email=email, notes=notes)
    console.print(f"[green]Contact added:[/green] {name}")


@contacts.command("remove")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
def contacts_remove(name: str, yes: bool) -> None:
    """Remove a contact."""
    if not yes:
        click.confirm(f"Remove contact '{name}'?", abort=True)
    ks = hbz.KeyStore()
    ks.remove_contact(name)
    console.print(f"[green]Removed:[/green] {name}")


@contacts.command("link")
@click.argument("contact_name")
@click.argument("fingerprint_prefix")
def contacts_link(contact_name: str, fingerprint_prefix: str) -> None:
    """Associate a key with a contact."""
    ks = hbz.KeyStore()
    fps = ks.resolve_recipient(fingerprint_prefix)
    if not fps:
        err_console.print(f"No key found for '{fingerprint_prefix}'.")
        sys.exit(1)
    ks.associate_key_with_contact(contact_name, fps[0])
    console.print(f"[green]Linked[/green] key {fps[0][:16]}.. to {contact_name}")


# ---------------------------------------------------------------------------
# Text encryption (convenience)
# ---------------------------------------------------------------------------

@cli.command("encrypt-text")
@click.option("--algorithm", "-a", type=click.Choice(["aes", "chacha"]), default="aes")
def encrypt_text(algorithm: str) -> None:
    """Encrypt text from stdin with a passphrase, output base64 to stdout."""
    import base64

    data = sys.stdin.buffer.read()
    pw = _prompt_passphrase(confirm=True)
    encrypted = hbz.encrypt_data(data, algorithm=algorithm, wrapping="password", passphrase=pw)
    click.echo(base64.b64encode(encrypted).decode())


@cli.command("decrypt-text")
def decrypt_text() -> None:
    """Decrypt base64 text from stdin with a passphrase, output plaintext to stdout."""
    import base64

    b64data = sys.stdin.read().strip()
    data = base64.b64decode(b64data)
    pw = _prompt_passphrase()
    plaintext = hbz.decrypt_data(data, passphrase=pw)
    sys.stdout.buffer.write(plaintext)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    cli()


if __name__ == "__main__":
    main()

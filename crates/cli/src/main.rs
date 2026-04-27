use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use dialoguer::{Confirm, Input, Password};
use indicatif::{ProgressBar, ProgressStyle};

use hb_zayfer_core::{
    ed25519, format, kdf, keystore, openpgp, passgen, rsa, shamir, shred, x25519, AppInfo,
    AppPaths, AuditLogger, AuditOperation, Config, ConfigSnapshot, KeyAlgorithm, KeyStore,
    KeyWrapping, SymmetricAlgorithm, WorkspaceSummary,
};
use serde_json::json;

mod platform_server;

/// HB_Zayfer — Encryption/Decryption Suite
///
/// A powerful, full-featured cryptographic toolkit supporting
/// RSA, AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, and OpenPGP.
#[derive(Parser)]
#[command(name = "hb-zayfer", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Output results as JSON (machine-readable)
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Key algorithm
        #[arg(short, long, value_enum)]
        algorithm: AlgorithmChoice,
        /// A human-readable label for the key
        #[arg(short, long)]
        label: String,
        /// Passphrase for protecting the private key (prompted if not given)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Encrypt a file or text
    Encrypt {
        /// Input file (use '-' for stdin)
        #[arg(short, long)]
        input: String,
        /// Output file (use '-' for stdout)
        #[arg(short, long)]
        output: String,
        /// Recipient key fingerprint or contact name (for public-key encryption)
        #[arg(short, long)]
        recipient: Option<String>,
        /// Symmetric algorithm
        #[arg(long, value_enum, default_value = "aes256gcm")]
        algorithm: SymAlgoChoice,
        /// Use password-based encryption instead of public-key
        #[arg(long)]
        password: bool,
        /// Read passphrase from a file (first line, trimmed)
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
        /// Enable compression before encryption
        #[arg(long)]
        compress: bool,
    },

    /// Decrypt a file or text
    Decrypt {
        /// Input file (use '-' for stdin)
        #[arg(short, long)]
        input: String,
        /// Output file (use '-' for stdout)
        #[arg(short, long)]
        output: String,
        /// Key fingerprint for decryption (auto-detected if possible)
        #[arg(short, long)]
        key: Option<String>,
        /// Passphrase for the private key (prompted if not given)
        #[arg(short, long)]
        passphrase: Option<String>,
        /// Read passphrase from a file (first line, trimmed)
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
    },

    /// Sign a file or message
    Sign {
        /// Input file to sign
        #[arg(short, long)]
        input: String,
        /// Key fingerprint for signing
        #[arg(short, long)]
        key: String,
        /// Output file for signature
        #[arg(short, long)]
        output: String,
    },

    /// Verify a signature
    Verify {
        /// Input file that was signed
        #[arg(short, long)]
        input: String,
        /// Signature file
        #[arg(short, long)]
        signature: String,
        /// Public key fingerprint of the signer
        #[arg(short, long)]
        key: String,
    },

    /// Key management commands
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Contact management commands
    Contacts {
        #[command(subcommand)]
        action: ContactsAction,
    },

    /// Keystore backup and recovery commands
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },

    /// Audit log commands
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Show Rust platform status and infrastructure summary
    Status,

    /// Run the Rust-native web platform
    Serve {
        /// Bind address
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port number
        #[arg(short = 'p', long, default_value_t = 8000)]
        port: u16,
        /// Disable token authentication (DANGEROUS — only for trusted loopback use)
        #[arg(long, default_value_t = false)]
        no_auth: bool,
        /// Use a specific authentication token instead of generating one
        #[arg(long)]
        token: Option<String>,
    },

    /// Inspect an HBZF encrypted file (show header metadata without decrypting)
    Inspect {
        /// Path to the HBZF file
        file: String,
    },

    /// Encrypt all files in a directory recursively
    EncryptDir {
        /// Input directory
        #[arg(short, long)]
        input: String,
        /// Output directory (mirrors input structure)
        #[arg(short, long)]
        output: String,
        /// Symmetric algorithm
        #[arg(long, value_enum, default_value = "aes256gcm")]
        algorithm: SymAlgoChoice,
        /// Read passphrase from a file
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
    },

    /// Decrypt all .hbzf files in a directory recursively
    DecryptDir {
        /// Input directory containing .hbzf files
        #[arg(short, long)]
        input: String,
        /// Output directory for decrypted files
        #[arg(short, long)]
        output: String,
        /// Read passphrase from a file
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Securely shred (overwrite + delete) files
    Shred {
        /// Files or directories to shred
        #[arg(required = true)]
        paths: Vec<String>,
        /// Number of overwrite passes
        #[arg(short, long, default_value_t = 3)]
        passes: u32,
        /// Recursively shred directories
        #[arg(short, long)]
        recursive: bool,
    },

    /// Generate a random password or passphrase
    Passgen {
        /// Password length (for random passwords)
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        /// Generate a passphrase instead (number of words)
        #[arg(short, long)]
        words: Option<usize>,
        /// Word separator for passphrases
        #[arg(long, default_value = "-")]
        separator: String,
        /// Exclude these characters from passwords
        #[arg(long, default_value = "")]
        exclude: String,
    },

    /// Split or combine secrets using Shamir's Secret Sharing
    Shamir {
        #[command(subcommand)]
        action: ShamirAction,
    },
}

#[derive(Subcommand)]
enum KeysAction {
    /// List all keys in the keyring
    List,
    /// Export a key
    Export {
        /// Key fingerprint (or prefix)
        fingerprint: String,
        /// Export format (pem, base64, hex, raw)
        #[arg(short, long, default_value = "pem")]
        format: String,
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import a key from a file
    Import {
        /// File to import
        file: String,
        /// Label for the imported key
        #[arg(short, long)]
        label: Option<String>,
        /// Override auto-detected algorithm (rsa2048, rsa4096, ed25519, x25519, pgp)
        #[arg(short, long)]
        algorithm: Option<String>,
    },
    /// Delete a key
    Delete {
        /// Key fingerprint
        fingerprint: String,
    },
}

#[derive(Subcommand)]
enum ContactsAction {
    /// List all contacts
    List,
    /// Add a contact
    Add {
        /// Contact name
        name: String,
        /// Associate a key fingerprint
        #[arg(short, long)]
        key: Option<String>,
        /// Email address
        #[arg(short, long)]
        email: Option<String>,
    },
    /// Remove a contact
    Remove {
        /// Contact name
        name: String,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Create an encrypted keystore backup
    Create {
        /// Output backup file path
        #[arg(short, long)]
        output: String,
        /// Optional backup label
        #[arg(short, long)]
        label: Option<String>,
        /// Backup passphrase (prompted if not supplied)
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    /// Restore keystore from an encrypted backup
    Restore {
        /// Input backup file path
        #[arg(short, long)]
        input: String,
        /// Backup passphrase (prompted if not supplied)
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    /// Verify a backup file integrity and passphrase
    Verify {
        /// Input backup file path
        #[arg(short, long)]
        input: String,
        /// Backup passphrase (prompted if not supplied)
        #[arg(short, long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Show recent audit log entries
    Show {
        /// Number of recent entries to show
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Verify audit log integrity chain
    Verify,
    /// Export audit log to a file
    Export {
        /// Output file path
        #[arg(short, long)]
        output: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show the current value of a config key
    Get {
        /// Config key (e.g., default-algorithm, kdf-preset, chunk-size)
        key: String,
    },
    /// Set a configuration value
    Set {
        /// Config key
        key: String,
        /// New value
        value: String,
    },
    /// List all configuration settings
    List,
    /// Reset configuration to defaults
    Reset,
    /// Show the path to the config file
    Path,
}

#[derive(Subcommand)]
enum ShamirAction {
    /// Split a secret into shares
    Split {
        /// The secret (text). Use - for stdin
        secret: String,
        /// Total number of shares to generate
        #[arg(short, long)]
        shares: u8,
        /// Minimum shares required to reconstruct
        #[arg(short, long)]
        threshold: u8,
    },
    /// Combine shares to reconstruct a secret
    Combine {
        /// Share strings (hex-encoded)
        #[arg(required = true)]
        shares: Vec<String>,
    },
}

#[derive(Clone, ValueEnum)]
enum AlgorithmChoice {
    Rsa2048,
    Rsa4096,
    Ed25519,
    X25519,
    Pgp,
}

#[derive(Clone, ValueEnum)]
enum SymAlgoChoice {
    Aes256gcm,
    Chacha20,
}

impl From<SymAlgoChoice> for SymmetricAlgorithm {
    fn from(c: SymAlgoChoice) -> Self {
        match c {
            SymAlgoChoice::Aes256gcm => SymmetricAlgorithm::Aes256Gcm,
            SymAlgoChoice::Chacha20 => SymmetricAlgorithm::ChaCha20Poly1305,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut keystore = KeyStore::open_default().context("Failed to open keystore")?;

    match cli.command {
        Commands::Keygen {
            algorithm,
            label,
            passphrase,
        } => cmd_keygen(&mut keystore, algorithm, &label, passphrase)?,

        Commands::Encrypt {
            input,
            output,
            recipient,
            algorithm,
            password,
            passphrase_file,
            compress,
        } => cmd_encrypt(
            &keystore,
            &input,
            &output,
            recipient,
            algorithm.into(),
            password,
            passphrase_file,
            compress,
        )?,

        Commands::Decrypt {
            input,
            output,
            key,
            passphrase,
            passphrase_file,
        } => cmd_decrypt(&keystore, &input, &output, key, passphrase, passphrase_file)?,

        Commands::Sign { input, key, output } => cmd_sign(&keystore, &input, &key, &output)?,

        Commands::Verify {
            input,
            signature,
            key,
        } => cmd_verify(&keystore, &input, &signature, &key)?,

        Commands::Keys { action } => match action {
            KeysAction::List => cmd_keys_list(&keystore, cli.json)?,
            KeysAction::Export {
                fingerprint,
                format,
                output,
            } => cmd_keys_export(&keystore, &fingerprint, &format, output)?,
            KeysAction::Import {
                file,
                label,
                algorithm,
            } => cmd_keys_import(&mut keystore, &file, label, algorithm)?,
            KeysAction::Delete { fingerprint } => cmd_keys_delete(&mut keystore, &fingerprint)?,
        },

        Commands::Contacts { action } => match action {
            ContactsAction::List => cmd_contacts_list(&keystore)?,
            ContactsAction::Add { name, key, email } => {
                cmd_contacts_add(&mut keystore, &name, key, email)?
            }
            ContactsAction::Remove { name } => cmd_contacts_remove(&mut keystore, &name)?,
        },

        Commands::Backup { action } => match action {
            BackupAction::Create {
                output,
                label,
                passphrase,
            } => cmd_backup_create(&keystore, &output, label, passphrase)?,
            BackupAction::Restore { input, passphrase } => {
                cmd_backup_restore(&keystore, &input, passphrase)?
            }
            BackupAction::Verify { input, passphrase } => cmd_backup_verify(&input, passphrase)?,
        },

        Commands::Audit { action } => match action {
            AuditAction::Show { limit } => cmd_audit_show(limit)?,
            AuditAction::Verify => cmd_audit_verify()?,
            AuditAction::Export { output } => cmd_audit_export(&output)?,
        },

        Commands::Config { action } => match action {
            ConfigAction::Get { key } => cmd_config_get(&key)?,
            ConfigAction::Set { key, value } => cmd_config_set(&key, &value)?,
            ConfigAction::List => cmd_config_list()?,
            ConfigAction::Reset => cmd_config_reset()?,
            ConfigAction::Path => cmd_config_path()?,
        },

        Commands::Status => cmd_status(cli.json)?,
        Commands::Serve {
            host,
            port,
            no_auth,
            token,
        } => {
            let auth_token = if no_auth {
                None
            } else {
                Some(token.unwrap_or_else(platform_server::generate_token))
            };
            platform_server::serve_with_auth(&host, port, auth_token)?
        }

        Commands::Inspect { file } => cmd_inspect(&file)?,

        Commands::EncryptDir {
            input,
            output,
            algorithm,
            passphrase_file,
        } => cmd_encrypt_dir(&input, &output, algorithm.into(), passphrase_file)?,

        Commands::DecryptDir {
            input,
            output,
            passphrase_file,
        } => cmd_decrypt_dir(&input, &output, passphrase_file)?,

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "hb-zayfer", &mut io::stdout());
        }

        Commands::Shred {
            paths,
            passes,
            recursive,
        } => {
            for path_str in &paths {
                let path = std::path::Path::new(path_str);
                if path.is_dir() && recursive {
                    let count = shred::shred_directory(path, passes)
                        .with_context(|| format!("shredding directory {path_str}"))?;
                    if cli.json {
                        println!("{}", json!({ "path": path_str, "files_shredded": count }));
                    } else {
                        println!("Shredded {} files in {}", count, path_str);
                    }
                } else if path.is_file() {
                    shred::shred_file(path, passes)
                        .with_context(|| format!("shredding {path_str}"))?;
                    if cli.json {
                        println!("{}", json!({ "path": path_str, "shredded": true }));
                    } else {
                        println!("Shredded: {}", path_str);
                    }
                } else {
                    eprintln!("Skipping {}: not a file (use -r for directories)", path_str);
                }
            }
        }

        Commands::Passgen {
            length,
            words,
            separator,
            exclude,
        } => {
            if let Some(word_count) = words {
                let phrase = passgen::generate_passphrase(word_count, &separator);
                let entropy = passgen::passphrase_entropy(word_count);
                if cli.json {
                    println!(
                        "{}",
                        json!({
                            "type": "passphrase",
                            "value": phrase,
                            "words": word_count,
                            "entropy_bits": entropy,
                        })
                    );
                } else {
                    println!("{}", phrase);
                    eprintln!("Entropy: {:.1} bits ({} words)", entropy, word_count);
                }
            } else {
                let policy = passgen::PasswordPolicy {
                    length,
                    uppercase: true,
                    lowercase: true,
                    digits: true,
                    symbols: true,
                    exclude: exclude.clone(),
                };
                let pw = passgen::generate_password(&policy);
                let entropy = passgen::estimate_entropy(&policy);
                if cli.json {
                    println!(
                        "{}",
                        json!({
                            "type": "password",
                            "value": pw,
                            "length": length,
                            "entropy_bits": entropy,
                        })
                    );
                } else {
                    println!("{}", pw);
                    eprintln!("Entropy: {:.1} bits ({} chars)", entropy, length);
                }
            }
        }

        Commands::Shamir { action } => match action {
            ShamirAction::Split {
                secret,
                shares,
                threshold,
            } => {
                let secret_bytes = if secret == "-" {
                    let mut buf = String::new();
                    io::stdin().read_to_string(&mut buf)?;
                    buf.into_bytes()
                } else {
                    secret.into_bytes()
                };
                let share_list = shamir::split(&secret_bytes, shares, threshold)
                    .context("Shamir split failed")?;
                if cli.json {
                    let encoded: Vec<String> = share_list
                        .iter()
                        .map(|s| hex::encode(shamir::encode_share(s)))
                        .collect();
                    println!(
                        "{}",
                        json!({
                            "shares": encoded,
                            "total": shares,
                            "threshold": threshold,
                        })
                    );
                } else {
                    println!("Split into {} shares (threshold {})", shares, threshold);
                    for s in &share_list {
                        println!("{}", hex::encode(shamir::encode_share(s)));
                    }
                }
            }
            ShamirAction::Combine { shares: share_strs } => {
                let decoded: Vec<shamir::Share> = share_strs
                    .iter()
                    .map(|s| {
                        let bytes = hex::decode(s).context("invalid hex in share")?;
                        shamir::decode_share(&bytes).context("invalid share format")
                    })
                    .collect::<Result<_, _>>()?;
                let secret = shamir::combine(&decoded).context("Shamir combine failed")?;
                let text = String::from_utf8_lossy(&secret);
                if cli.json {
                    println!("{}", json!({ "secret": text }));
                } else {
                    println!("{}", text);
                }
            }
        },
    }

    Ok(())
}

// -- Command implementations --

fn cmd_status(json_output: bool) -> Result<()> {
    let info = AppInfo::current();
    let paths = AppPaths::current()?;
    let summary = WorkspaceSummary::collect()?;
    let config = ConfigSnapshot::load()?;

    if json_output {
        println!(
            "{}",
            json!({
                "brand_name": info.brand_name,
                "version": info.version,
                "binary_name": info.binary_name,
                "app_home": paths.app_home,
                "config_path": paths.config_path,
                "audit_path": paths.audit_path,
                "key_count": summary.key_count,
                "contact_count": summary.contact_count,
                "audit_count": summary.audit_count,
                "default_algorithm": config.default_algorithm,
                "kdf_preset": config.kdf_preset,
                "chunk_size": config.chunk_size,
                "audit_enabled": config.audit_enabled,
            })
        );
    } else {
        println!("{}", info.window_title());
        println!("Binary: {}", info.binary_name);
        println!("App home: {}", paths.app_home.display());
        println!("Config: {}", paths.config_path.display());
        println!("Audit log: {}", paths.audit_path.display());
        println!();
        println!("Keys: {}", summary.key_count);
        println!("Contacts: {}", summary.contact_count);
        println!("Audit entries: {}", summary.audit_count);
        println!("Default algorithm: {}", config.default_algorithm);
        println!("KDF preset: {}", config.kdf_preset);
    }

    Ok(())
}

fn cmd_keygen(
    keystore: &mut KeyStore,
    algorithm: AlgorithmChoice,
    label: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let passphrase = match passphrase {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter passphrase for the private key")
            .with_confirmation("Confirm passphrase", "Passphrases don't match")
            .interact()?,
    };

    let user_id: Option<String> = if matches!(algorithm, AlgorithmChoice::Pgp) {
        Some(
            Input::<String>::new()
                .with_prompt("User ID (e.g., 'Name <email@example.com>')")
                .interact_text()?,
        )
    } else {
        None
    };

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.set_message("Generating key pair...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let requested_algorithm = match algorithm {
        AlgorithmChoice::Rsa2048 => "rsa2048",
        AlgorithmChoice::Rsa4096 => "rsa4096",
        AlgorithmChoice::Ed25519 => "ed25519",
        AlgorithmChoice::X25519 => "x25519",
        AlgorithmChoice::Pgp => "pgp",
    };

    let created = hb_zayfer_core::services::generate_and_store_key(
        keystore,
        requested_algorithm,
        label,
        &passphrase,
        user_id.as_deref(),
    )?;

    pb.finish_with_message(format!("{} key generated", created.algorithm));
    println!("Fingerprint: {}", created.fingerprint);
    println!("Label: {}", created.label);
    if let Some(user_id) = user_id {
        println!("User ID: {user_id}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_encrypt(
    keystore: &KeyStore,
    input: &str,
    output: &str,
    recipient: Option<String>,
    algorithm: SymmetricAlgorithm,
    use_password: bool,
    passphrase_file: Option<String>,
    compress: bool,
) -> Result<()> {
    let plaintext = read_input(input)?;

    if use_password {
        // Password-based encryption
        let password =
            resolve_passphrase(None, passphrase_file, "Enter encryption password", true)?;

        let kdf_params = kdf::KdfParams::default();
        let salt = kdf::generate_salt(16);
        let key = kdf::derive_key(password.as_bytes(), &salt, &kdf_params)?;

        let params = format::EncryptParams {
            algorithm,
            wrapping: KeyWrapping::Password,
            symmetric_key: key,
            kdf_params: Some(kdf_params),
            kdf_salt: Some(salt),
            wrapped_key: None,
            ephemeral_public: None,
            chunk_size: None,
            compress,
        };

        let mut input_cursor = io::Cursor::new(&plaintext);
        let mut output_buf = Vec::new();

        let pb = create_progress_bar(plaintext.len() as u64);
        format::encrypt_stream(
            &mut input_cursor,
            &mut output_buf,
            &params,
            plaintext.len() as u64,
            Some(&mut |bytes| pb.set_position(bytes)),
        )?;
        pb.finish_with_message("Encryption complete");

        write_output(output, &output_buf)?;
        audit_log(
            AuditOperation::FileEncrypted {
                algorithm: format!("{:?}", algorithm),
                filename: Some(input.to_string()),
                size_bytes: Some(plaintext.len() as u64),
            },
            Some("source=cli"),
        );
    } else if let Some(recipient_name) = recipient {
        // Public-key encryption (X25519 ECDH)
        let fingerprints = keystore.resolve_recipient(&recipient_name);
        if fingerprints.is_empty() {
            bail!("No key found for recipient: {recipient_name}");
        }
        let fp = &fingerprints[0];
        let metadata = keystore
            .get_key_metadata(fp)
            .ok_or_else(|| anyhow::anyhow!("Key metadata not found for {fp}"))?;

        match metadata.algorithm {
            KeyAlgorithm::X25519 => {
                let pub_bytes = keystore.load_public_key(fp)?;
                let their_public = x25519::import_public_key_raw(&pub_bytes)?;
                let (eph_public, symmetric_key) = x25519::encrypt_key_agreement(&their_public)?;

                let params = format::EncryptParams {
                    algorithm,
                    wrapping: KeyWrapping::X25519Ecdh,
                    symmetric_key: symmetric_key.to_vec(),
                    kdf_params: None,
                    kdf_salt: None,
                    wrapped_key: None,
                    ephemeral_public: Some(x25519::export_public_key_raw(&eph_public)),
                    chunk_size: None,
                    compress,
                };

                let mut input_cursor = io::Cursor::new(&plaintext);
                let mut output_buf = Vec::new();
                format::encrypt_stream(
                    &mut input_cursor,
                    &mut output_buf,
                    &params,
                    plaintext.len() as u64,
                    None,
                )?;
                write_output(output, &output_buf)?;
                println!("Encrypted with X25519 to {}", &fp[..16]);
                audit_log(
                    AuditOperation::FileEncrypted {
                        algorithm: format!("{:?}", algorithm),
                        filename: Some(input.to_string()),
                        size_bytes: Some(plaintext.len() as u64),
                    },
                    Some("source=cli"),
                );
            }
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
                let pub_bytes = keystore.load_public_key(fp)?;
                let pub_pem = String::from_utf8(pub_bytes)?;
                let rsa_pub = rsa::import_public_key_pem(&pub_pem)?;

                // Generate random symmetric key, encrypt it with RSA
                let mut sym_key = vec![0u8; 32];
                rand::RngCore::fill_bytes(&mut rand_core::OsRng, &mut sym_key);
                let wrapped = rsa::encrypt(&rsa_pub, &sym_key)?;

                let params = format::EncryptParams {
                    algorithm,
                    wrapping: KeyWrapping::RsaOaep,
                    symmetric_key: sym_key,
                    kdf_params: None,
                    kdf_salt: None,
                    wrapped_key: Some(wrapped),
                    ephemeral_public: None,
                    chunk_size: None,
                    compress,
                };

                let mut input_cursor = io::Cursor::new(&plaintext);
                let mut output_buf = Vec::new();
                format::encrypt_stream(
                    &mut input_cursor,
                    &mut output_buf,
                    &params,
                    plaintext.len() as u64,
                    None,
                )?;
                write_output(output, &output_buf)?;
                println!("Encrypted with RSA to {}", &fp[..16]);
                audit_log(
                    AuditOperation::FileEncrypted {
                        algorithm: format!("{:?}", algorithm),
                        filename: Some(input.to_string()),
                        size_bytes: Some(plaintext.len() as u64),
                    },
                    Some("source=cli"),
                );
            }
            _ => bail!(
                "Key algorithm {:?} not supported for encryption",
                metadata.algorithm
            ),
        }
    } else {
        bail!("Specify --recipient for public-key encryption or --password for password-based encryption");
    }

    Ok(())
}

fn cmd_decrypt(
    keystore: &KeyStore,
    input: &str,
    output: &str,
    key_fp: Option<String>,
    passphrase: Option<String>,
    passphrase_file: Option<String>,
) -> Result<()> {
    let ciphertext = read_input(input)?;
    let mut cursor = io::Cursor::new(&ciphertext);
    let header = format::read_header(&mut cursor)?;

    let symmetric_key = match header.wrapping {
        KeyWrapping::Password => {
            let password = resolve_passphrase(
                passphrase,
                passphrase_file,
                "Enter decryption password",
                false,
            )?;
            let salt = header
                .kdf_salt
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing KDF salt in file"))?;
            let kdf_params = header
                .kdf_params
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing KDF params in file"))?;
            kdf::derive_key(password.as_bytes(), salt, kdf_params)?
        }
        KeyWrapping::X25519Ecdh => {
            let fp =
                key_fp.ok_or_else(|| anyhow::anyhow!("Specify --key for X25519 decryption"))?;
            let passphrase_str = resolve_passphrase(
                None,
                passphrase_file.clone(),
                "Enter passphrase for private key",
                false,
            )?;
            let priv_bytes = keystore.load_private_key(&fp, passphrase_str.as_bytes())?;
            let secret = x25519::import_secret_key_raw(&priv_bytes)?;
            let eph_pub_bytes = header
                .ephemeral_public
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing ephemeral public key"))?;
            let eph_pub = x25519::import_public_key_raw(eph_pub_bytes)?;
            let sym_key = x25519::decrypt_key_agreement(&secret, &eph_pub)?;
            sym_key.to_vec()
        }
        KeyWrapping::RsaOaep => {
            let fp = key_fp.ok_or_else(|| anyhow::anyhow!("Specify --key for RSA decryption"))?;
            let passphrase_str = resolve_passphrase(
                None,
                passphrase_file,
                "Enter passphrase for private key",
                false,
            )?;
            let priv_bytes = keystore.load_private_key(&fp, passphrase_str.as_bytes())?;
            let priv_pem = String::from_utf8(priv_bytes)?;
            let rsa_priv = rsa::import_private_key_pem(&priv_pem)?;
            let wrapped = header
                .wrapped_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing wrapped key"))?;
            rsa::decrypt(&rsa_priv, wrapped)?
        }
    };

    let mut output_buf = Vec::new();
    let pb = create_progress_bar(header.plaintext_len);
    format::decrypt_stream(
        &mut cursor,
        &mut output_buf,
        &header,
        &symmetric_key,
        Some(&mut |bytes| pb.set_position(bytes)),
    )?;
    pb.finish_with_message("Decryption complete");

    write_output(output, &output_buf)?;
    audit_log(
        AuditOperation::FileDecrypted {
            algorithm: format!("{:?}", header.algorithm),
            filename: Some(input.to_string()),
            size_bytes: Some(output_buf.len() as u64),
        },
        Some("source=cli"),
    );
    Ok(())
}

fn cmd_sign(keystore: &KeyStore, input: &str, key_fp: &str, output: &str) -> Result<()> {
    let message = read_input(input)?;

    let passphrase = Password::new()
        .with_prompt("Enter passphrase for signing key")
        .interact()?;

    let metadata = keystore
        .get_key_metadata(key_fp)
        .ok_or_else(|| anyhow::anyhow!("Key not found: {key_fp}"))?;

    let priv_bytes = keystore.load_private_key(key_fp, passphrase.as_bytes())?;

    let signature = match metadata.algorithm {
        KeyAlgorithm::Ed25519 => {
            let priv_pem = String::from_utf8(priv_bytes)?;
            let signing_key = ed25519::import_signing_key_pem(&priv_pem)?;
            ed25519::sign(&signing_key, &message)
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let priv_pem = String::from_utf8(priv_bytes)?;
            let rsa_priv = rsa::import_private_key_pem(&priv_pem)?;
            rsa::sign(&rsa_priv, &message)?
        }
        KeyAlgorithm::Pgp => {
            let armor = String::from_utf8(priv_bytes)?;
            let cert = openpgp::import_cert(&armor)?;
            openpgp::sign_message(&message, &cert)?
        }
        _ => bail!(
            "Algorithm {:?} not supported for signing",
            metadata.algorithm
        ),
    };

    write_output(output, &signature)?;
    println!("Signature written to: {output}");
    audit_log(
        AuditOperation::DataSigned {
            algorithm: metadata.algorithm.to_string(),
            fingerprint: key_fp.to_string(),
        },
        Some("source=cli"),
    );
    Ok(())
}

fn cmd_verify(keystore: &KeyStore, input: &str, sig_file: &str, key_fp: &str) -> Result<()> {
    let message = read_input(input)?;
    let signature = fs::read(sig_file).context("Failed to read signature file")?;

    let metadata = keystore
        .get_key_metadata(key_fp)
        .ok_or_else(|| anyhow::anyhow!("Key not found: {key_fp}"))?;

    let pub_bytes = keystore.load_public_key(key_fp)?;

    let valid = match metadata.algorithm {
        KeyAlgorithm::Ed25519 => {
            let pub_pem = String::from_utf8(pub_bytes)?;
            let vk = ed25519::import_verifying_key_pem(&pub_pem)?;
            ed25519::verify(&vk, &message, &signature)?
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let pub_pem = String::from_utf8(pub_bytes)?;
            let rsa_pub = rsa::import_public_key_pem(&pub_pem)?;
            rsa::verify(&rsa_pub, &message, &signature)?
        }
        KeyAlgorithm::Pgp => {
            let armor = String::from_utf8(pub_bytes)?;
            let cert = openpgp::import_cert(&armor)?;
            let (_content, is_valid) = openpgp::verify_message(&signature, &[cert])?;
            is_valid
        }
        _ => bail!(
            "Algorithm {:?} not supported for verification",
            metadata.algorithm
        ),
    };

    if valid {
        println!("✓ Signature is VALID");
    } else {
        println!("✗ Signature is INVALID");
    }
    audit_log(
        AuditOperation::SignatureVerified {
            algorithm: metadata.algorithm.to_string(),
            fingerprint: key_fp.to_string(),
            valid,
        },
        Some("source=cli"),
    );
    if !valid {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_keys_list(keystore: &KeyStore, as_json: bool) -> Result<()> {
    let keys = keystore.list_keys();
    if as_json {
        let items: Vec<serde_json::Value> = keys
            .iter()
            .map(|k| {
                json!({
                    "fingerprint": k.fingerprint,
                    "algorithm": k.algorithm,
                    "label": k.label,
                    "has_private": k.has_private,
                    "has_public": k.has_public,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if keys.is_empty() {
        println!("No keys in keyring. Use 'hb-zayfer keygen' to generate one.");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<8} {:<8} LABEL",
        "FINGERPRINT", "ALGORITHM", "PRIVATE", "PUBLIC"
    );
    println!("{}", "-".repeat(70));
    for k in keys {
        let fp_short = if k.fingerprint.len() > 16 {
            &k.fingerprint[..16]
        } else {
            &k.fingerprint
        };
        println!(
            "{:<20} {:<10} {:<8} {:<8} {}",
            format!("{fp_short}..."),
            k.algorithm,
            if k.has_private { "yes" } else { "no" },
            if k.has_public { "yes" } else { "no" },
            k.label,
        );
    }
    Ok(())
}

fn cmd_keys_export(
    keystore: &KeyStore,
    fingerprint: &str,
    format: &str,
    output: Option<String>,
) -> Result<()> {
    let pub_bytes = keystore.load_public_key(fingerprint)?;

    let formatted: Vec<u8> = match format {
        "pem" | "auto" => {
            // If data is already valid UTF-8 text (PEM, armor, etc.), use as-is.
            // Otherwise base64-encode it.
            if let Ok(text) = String::from_utf8(pub_bytes.clone()) {
                text.into_bytes()
            } else {
                format!("{}\n", BASE64.encode(&pub_bytes)).into_bytes()
            }
        }
        "base64" | "b64" => format!("{}\n", BASE64.encode(&pub_bytes)).into_bytes(),
        "hex" => {
            use std::fmt::Write;
            let mut s = String::with_capacity(pub_bytes.len() * 2 + 1);
            for b in &pub_bytes {
                write!(s, "{b:02x}").unwrap();
            }
            s.push('\n');
            s.into_bytes()
        }
        "raw" | "bin" => pub_bytes.clone(),
        _ => anyhow::bail!("Unknown format '{format}'. Supported: pem (default), base64, hex, raw"),
    };

    match output {
        Some(path) => {
            fs::write(&path, &formatted)?;
            println!("Public key exported to: {path}");
        }
        None => {
            if format == "raw" || format == "bin" {
                use std::io::Write;
                std::io::stdout().write_all(&formatted)?;
            } else if let Ok(text) = String::from_utf8(formatted) {
                print!("{text}");
            } else {
                println!("{}", BASE64.encode(&pub_bytes));
            }
        }
    }
    Ok(())
}

fn cmd_keys_import(
    keystore: &mut KeyStore,
    file: &str,
    label: Option<String>,
    algorithm_override: Option<String>,
) -> Result<()> {
    let data = fs::read(file).context("Failed to read key file")?;
    let label = label.unwrap_or_else(|| file.to_string());

    // If user explicitly specified an algorithm, use it
    let algorithm = if let Some(ref algo_str) = algorithm_override {
        match algo_str.to_lowercase().as_str() {
            "rsa2048" | "rsa-2048" => KeyAlgorithm::Rsa2048,
            "rsa4096" | "rsa-4096" => KeyAlgorithm::Rsa4096,
            "ed25519" => KeyAlgorithm::Ed25519,
            "x25519" => KeyAlgorithm::X25519,
            "pgp" | "openpgp" => KeyAlgorithm::Pgp,
            other => anyhow::bail!(
                "Unknown algorithm '{other}'. Supported: rsa2048, rsa4096, ed25519, x25519, pgp"
            ),
        }
    } else {
        // Auto-detect from file content
        let fmt = keystore::detect_key_format(&data);
        match &fmt {
            keystore::KeyFormat::OpenPgpArmor => KeyAlgorithm::Pgp,
            keystore::KeyFormat::OpenSsh => {
                if let Ok(text) = std::str::from_utf8(&data) {
                    if text.starts_with("ssh-rsa") {
                        // Try to determine RSA key size from base64 payload length
                        KeyAlgorithm::Rsa4096 // default to 4096 for imported RSA
                    } else {
                        KeyAlgorithm::Ed25519
                    }
                } else {
                    KeyAlgorithm::Ed25519
                }
            }
            _ => {
                if let Ok(text) = std::str::from_utf8(&data) {
                    if text.contains("RSA") {
                        // Parse the actual RSA modulus to determine key size.
                        if let Ok(size) = rsa::detect_key_size(text) {
                            match size {
                                rsa::RsaKeySize::Rsa4096 => KeyAlgorithm::Rsa4096,
                                rsa::RsaKeySize::Rsa2048 => KeyAlgorithm::Rsa2048,
                            }
                        } else {
                            KeyAlgorithm::Rsa4096 // fallback for unparseable RSA PEM
                        }
                    } else {
                        KeyAlgorithm::Ed25519
                    }
                } else if data.len() == 32 {
                    // Raw 32-byte files are likely X25519 public keys
                    KeyAlgorithm::X25519
                } else {
                    KeyAlgorithm::Ed25519
                }
            }
        }
    };

    let fp = keystore::compute_fingerprint(&data);
    println!("Key imported:");
    println!("  Fingerprint: {fp}");
    println!("  Algorithm: {algorithm:?}");
    println!("  Label: {label}");
    keystore.store_public_key(&fp, &data, algorithm, &label)?;
    Ok(())
}

fn cmd_keys_delete(keystore: &mut KeyStore, fingerprint: &str) -> Result<()> {
    let confirm = Confirm::new()
        .with_prompt(format!("Delete key {fingerprint}? This cannot be undone"))
        .default(false)
        .interact()?;

    if confirm {
        keystore.delete_key(fingerprint)?;
        println!("Key deleted: {fingerprint}");
    } else {
        println!("Aborted.");
    }
    Ok(())
}

fn cmd_contacts_list(keystore: &KeyStore) -> Result<()> {
    let contacts = keystore.list_contacts();
    if contacts.is_empty() {
        println!("No contacts. Use 'hb-zayfer contacts add' to add one.");
        return Ok(());
    }

    println!("{:<20} {:<30} KEYS", "NAME", "EMAIL");
    println!("{}", "-".repeat(60));
    for c in contacts {
        println!(
            "{:<20} {:<30} {}",
            c.name,
            c.email.as_deref().unwrap_or("-"),
            c.key_fingerprints.len(),
        );
    }
    Ok(())
}

fn cmd_contacts_add(
    keystore: &mut KeyStore,
    name: &str,
    key: Option<String>,
    email: Option<String>,
) -> Result<()> {
    keystore.add_contact(name, email.as_deref(), None)?;
    if let Some(fp) = key {
        keystore.associate_key_with_contact(name, &fp)?;
        println!("Contact '{name}' added with key {fp}");
    } else {
        println!("Contact '{name}' added");
    }
    Ok(())
}

fn cmd_contacts_remove(keystore: &mut KeyStore, name: &str) -> Result<()> {
    keystore.remove_contact(name)?;
    println!("Contact '{name}' removed");
    Ok(())
}

fn cmd_backup_create(
    keystore: &KeyStore,
    output: &str,
    label: Option<String>,
    passphrase: Option<String>,
) -> Result<()> {
    let passphrase = match passphrase {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter backup passphrase")
            .with_confirmation("Confirm backup passphrase", "Passphrases don't match")
            .interact()?,
    };

    keystore.create_backup(&PathBuf::from(output), passphrase.as_bytes(), label)?;
    println!("Backup created: {output}");
    Ok(())
}

fn cmd_backup_restore(keystore: &KeyStore, input: &str, passphrase: Option<String>) -> Result<()> {
    let passphrase = match passphrase {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter backup passphrase")
            .interact()?,
    };

    let manifest = KeyStore::restore_backup(
        &PathBuf::from(input),
        passphrase.as_bytes(),
        keystore.base_path(),
    )?;
    println!("Backup restored successfully");
    println!("  Created at: {}", manifest.created_at.to_rfc3339());
    println!("  Private keys: {}", manifest.private_key_count);
    println!("  Public keys: {}", manifest.public_key_count);
    println!("  Contacts: {}", manifest.contact_count);
    Ok(())
}

fn cmd_backup_verify(input: &str, passphrase: Option<String>) -> Result<()> {
    let passphrase = match passphrase {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter backup passphrase")
            .interact()?,
    };

    let manifest = KeyStore::verify_backup(&PathBuf::from(input), passphrase.as_bytes())?;
    println!("Backup verification passed");
    println!("  Version: {}", manifest.version);
    println!("  Created at: {}", manifest.created_at.to_rfc3339());
    if let Some(label) = manifest.label {
        println!("  Label: {label}");
    }
    Ok(())
}

fn cmd_audit_show(limit: usize) -> Result<()> {
    let logger = AuditLogger::default_location()?;
    let entries = logger.recent_entries(limit)?;

    if entries.is_empty() {
        println!("No audit entries found.");
        return Ok(());
    }

    println!("{:<28} {:<80} NOTE", "TIMESTAMP", "OPERATION");
    println!("{}", "-".repeat(128));
    for entry in entries {
        let op = format!("{:?}", entry.operation);
        let note = entry.note.unwrap_or_else(|| "-".to_string());
        println!("{:<28} {:<80} {}", entry.timestamp.to_rfc3339(), op, note,);
    }
    Ok(())
}

fn cmd_audit_verify() -> Result<()> {
    let logger = AuditLogger::default_location()?;
    let valid = logger.verify_integrity()?;
    if valid {
        println!("Audit log integrity OK");
    } else {
        println!("Audit log integrity FAILED");
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_audit_export(output: &str) -> Result<()> {
    let logger = AuditLogger::default_location()?;
    logger.export(&PathBuf::from(output))?;
    println!("Audit log exported to: {output}");
    Ok(())
}

// -- Config commands --

fn cmd_config_get(key: &str) -> Result<()> {
    let config = Config::load_default()?;
    let value = config.get(key)?;
    println!("{value}");
    Ok(())
}

fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    let mut config = Config::load_default()?;
    config.set(key, value)?;
    config.save_default()?;
    println!("{key} = {value}");
    audit_log(
        AuditOperation::ConfigModified {
            setting: format!("{key}={value}"),
        },
        Some("source=cli"),
    );
    Ok(())
}

fn cmd_config_list() -> Result<()> {
    let config = Config::load_default()?;
    let keys = [
        "default-algorithm",
        "kdf-preset",
        "chunk-size",
        "audit-log",
        "dark-mode",
        "color",
        "progress",
        "verbosity",
    ];
    println!("{:<25} VALUE", "KEY");
    println!("{}", "-".repeat(50));
    for key in keys {
        let value = config.get(key).unwrap_or_else(|_| "<unset>".into());
        println!("{:<25} {}", key, value);
    }
    Ok(())
}

fn cmd_config_reset() -> Result<()> {
    let config = Config::default();
    config.save_default()?;
    println!("Configuration reset to defaults");
    Ok(())
}

fn cmd_config_path() -> Result<()> {
    let path = Config::default_path()?;
    println!("{}", path.display());
    Ok(())
}

// -- Inspect command --

fn cmd_inspect(file: &str) -> Result<()> {
    let data = fs::read(file).with_context(|| format!("Failed to read: {file}"))?;
    let mut cursor = io::Cursor::new(&data);
    let header = format::read_header(&mut cursor)
        .with_context(|| "Failed to parse HBZF header. Is this an encrypted file?")?;

    println!("HBZF File: {file}");
    println!("{}", "-".repeat(50));
    println!("Format version:    {}", header.version);
    println!("Cipher:            {:?}", header.algorithm);
    println!(
        "Compression:       {}",
        if header.compressed { "enabled" } else { "none" }
    );
    println!("Key wrapping:      {:?}", header.wrapping);
    if let Some(ref kdf_algo) = header.kdf_algorithm {
        println!("KDF:               {:?}", kdf_algo);
    }
    if let Some(ref kdf_p) = header.kdf_params {
        println!("KDF params:        {:?}", kdf_p);
    }
    println!("Plaintext size:    {} bytes", header.plaintext_len);
    let encrypted_size = data.len() as u64;
    println!("Encrypted size:    {} bytes", encrypted_size);
    if header.plaintext_len > 0 {
        let ratio = encrypted_size as f64 / header.plaintext_len as f64;
        println!("Overhead ratio:    {:.2}x", ratio);
    }
    if let Some(wrapped_key) = &header.wrapped_key {
        println!("Wrapped key:       present ({} bytes)", wrapped_key.len());
    }
    if header.ephemeral_public.is_some() {
        println!("Ephemeral pubkey:  present (32 bytes)");
    }
    Ok(())
}

// -- Utilities --

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("Failed to read: {path}"))
    }
}

/// Read a passphrase from a file (first line, trimmed).
fn read_passphrase_file(path: &str) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read passphrase file: {path}"))?;
    let first_line = content.lines().next().unwrap_or("").trim().to_string();
    if first_line.is_empty() {
        bail!("Passphrase file is empty: {path}");
    }
    Ok(first_line)
}

/// Resolve a passphrase from explicit string, file, or prompt.
fn resolve_passphrase(
    explicit: Option<String>,
    passphrase_file: Option<String>,
    prompt: &str,
    confirm: bool,
) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(f) = passphrase_file {
        return read_passphrase_file(&f);
    }
    if confirm {
        Ok(Password::new()
            .with_prompt(prompt)
            .with_confirmation(format!("Confirm {}", prompt.to_lowercase()), "Don't match")
            .interact()?)
    } else {
        Ok(Password::new().with_prompt(prompt).interact()?)
    }
}

fn write_output(path: &str, data: &[u8]) -> Result<()> {
    if path == "-" {
        io::stdout().write_all(data)?;
        io::stdout().flush()?;
    } else {
        fs::write(path, data).with_context(|| format!("Failed to write: {path}"))?;
    }
    Ok(())
}

fn create_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb
}

fn audit_log(operation: AuditOperation, notes: Option<&str>) {
    if let Ok(logger) = AuditLogger::default_location() {
        let _ = logger.log(operation, notes.map(|s| s.to_string()));
    }
}

// -- Batch directory encryption/decryption --

fn cmd_encrypt_dir(
    input_dir: &str,
    output_dir: &str,
    algorithm: SymmetricAlgorithm,
    passphrase_file: Option<String>,
) -> Result<()> {
    let in_path = std::path::Path::new(input_dir);
    let out_path = std::path::Path::new(output_dir);

    if !in_path.is_dir() {
        bail!("Input path is not a directory: {input_dir}");
    }

    let passphrase = resolve_passphrase(None, passphrase_file, "Encryption passphrase", true)?;

    // Collect all files recursively
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(in_path, &mut files)?;

    if files.is_empty() {
        println!("No files found in {input_dir}");
        return Ok(());
    }

    println!(
        "Encrypting {} files from {} → {}",
        files.len(),
        input_dir,
        output_dir
    );
    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut success = 0usize;
    let mut failed = 0usize;

    for file in &files {
        let relative = file.strip_prefix(in_path).unwrap_or(file);
        let dest = out_path.join(relative).with_extension(format!(
            "{}.hbzf",
            file.extension().unwrap_or_default().to_string_lossy()
        ));

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        let kdf_params = kdf::KdfParams::default();
        let salt = kdf::generate_salt(16);
        let key =
            kdf::derive_key(passphrase.as_bytes(), &salt, &kdf_params).context("KDF failed")?;

        let params = format::EncryptParams {
            algorithm,
            wrapping: KeyWrapping::Password,
            symmetric_key: key,
            kdf_params: Some(kdf_params),
            kdf_salt: Some(salt),
            wrapped_key: None,
            ephemeral_public: None,
            chunk_size: None,
            compress: false,
        };

        let file_len = fs::metadata(file)?.len();
        match (|| -> Result<()> {
            let mut reader = fs::File::open(file)?;
            let mut writer = fs::File::create(&dest)?;
            format::encrypt_stream(&mut reader, &mut writer, &params, file_len, None)?;
            Ok(())
        })() {
            Ok(()) => success += 1,
            Err(e) => {
                eprintln!("  FAILED {}: {e}", relative.display());
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    println!(
        "Done: {success} encrypted, {failed} failed (of {} total)",
        files.len()
    );
    audit_log(
        AuditOperation::FileEncrypted {
            algorithm: format!("{algorithm:?}"),
            filename: Some(input_dir.to_string()),
            size_bytes: Some(files.len() as u64),
        },
        Some(&format!("batch encrypt-dir: {success} ok, {failed} failed")),
    );
    Ok(())
}

fn cmd_decrypt_dir(
    input_dir: &str,
    output_dir: &str,
    passphrase_file: Option<String>,
) -> Result<()> {
    let in_path = std::path::Path::new(input_dir);
    let out_path = std::path::Path::new(output_dir);

    if !in_path.is_dir() {
        bail!("Input path is not a directory: {input_dir}");
    }

    let passphrase = resolve_passphrase(None, passphrase_file, "Decryption passphrase", false)?;

    // Collect .hbzf files only
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(in_path, &mut files)?;
    files.retain(|f| f.extension().is_some_and(|e| e == "hbzf"));

    if files.is_empty() {
        println!("No .hbzf files found in {input_dir}");
        return Ok(());
    }

    println!(
        "Decrypting {} files from {} → {}",
        files.len(),
        input_dir,
        output_dir
    );
    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut success = 0usize;
    let mut failed = 0usize;

    for file in &files {
        let relative = file.strip_prefix(in_path).unwrap_or(file);
        // Remove .hbzf extension for output
        let dest = out_path.join(relative).with_extension("");

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        match (|| -> Result<()> {
            let mut reader = fs::File::open(file)?;
            let header = format::read_header(&mut reader)?;
            let sym_key = match header.wrapping {
                KeyWrapping::Password => {
                    let kp = header
                        .kdf_params
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing KDF params"))?;
                    let salt = header
                        .kdf_salt
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing salt"))?;
                    kdf::derive_key(passphrase.as_bytes(), salt, kp)?
                }
                _ => bail!("Batch decrypt only supports password-encrypted files"),
            };
            let mut writer = fs::File::create(&dest)?;
            format::decrypt_stream(&mut reader, &mut writer, &header, &sym_key, None)?;
            Ok(())
        })() {
            Ok(()) => success += 1,
            Err(e) => {
                eprintln!("  FAILED {}: {e}", relative.display());
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    println!(
        "Done: {success} decrypted, {failed} failed (of {} total)",
        files.len()
    );
    audit_log(
        AuditOperation::FileDecrypted {
            algorithm: "batch".to_string(),
            filename: Some(input_dir.to_string()),
            size_bytes: Some(files.len() as u64),
        },
        Some(&format!("batch decrypt-dir: {success} ok, {failed} failed")),
    );
    Ok(())
}

/// Recursively collect all files in a directory tree.
fn collect_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

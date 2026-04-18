//! OpenPGP operations using sequoia-openpgp.
//!
//! Provides PGP key generation, encryption, decryption, signing, and verification
//! for interoperability with GPG and other OpenPGP implementations.

use openpgp::cert::prelude::*;
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::serialize::Marshal;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use std::io::{Read, Write};

use crate::error::{HbError, HbResult};

/// Policy for validating certificates.
static POLICY: &StandardPolicy = &StandardPolicy::new();

/// Generate a new OpenPGP certificate with the given user ID.
///
/// Returns the certificate (containing both public and private key material).
pub fn generate_cert(user_id: &str) -> HbResult<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(user_id)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .map_err(|e| HbError::OpenPgp(format!("Certificate generation: {e}")))?;
    Ok(cert)
}

/// Export a certificate's public key as ASCII-armored text.
pub fn export_public_key(cert: &openpgp::Cert) -> HbResult<String> {
    let mut buf = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(&mut buf, openpgp::armor::Kind::PublicKey)
            .map_err(|e| HbError::OpenPgp(format!("Armor writer: {e}")))?;
        cert.serialize(&mut writer)
            .map_err(|e| HbError::OpenPgp(format!("Serialize public key: {e}")))?;
        writer
            .finalize()
            .map_err(|e| HbError::OpenPgp(format!("Finalize armor: {e}")))?;
    }
    String::from_utf8(buf).map_err(|e| HbError::OpenPgp(format!("UTF-8 conversion: {e}")))
}

/// Export a certificate including secret key material as ASCII-armored text.
pub fn export_secret_key(cert: &openpgp::Cert) -> HbResult<String> {
    let mut buf = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(&mut buf, openpgp::armor::Kind::SecretKey)
            .map_err(|e| HbError::OpenPgp(format!("Armor writer: {e}")))?;
        cert.as_tsk()
            .serialize(&mut writer)
            .map_err(|e| HbError::OpenPgp(format!("Serialize secret key: {e}")))?;
        writer
            .finalize()
            .map_err(|e| HbError::OpenPgp(format!("Finalize armor: {e}")))?;
    }
    String::from_utf8(buf).map_err(|e| HbError::OpenPgp(format!("UTF-8 conversion: {e}")))
}

/// Import a certificate from ASCII-armored text.
pub fn import_cert(armored: &str) -> HbResult<openpgp::Cert> {
    openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| HbError::OpenPgp(format!("Import certificate: {e}")))
}

/// Get the fingerprint of a certificate.
pub fn cert_fingerprint(cert: &openpgp::Cert) -> String {
    cert.fingerprint().to_hex()
}

/// Get the primary user ID of a certificate.
pub fn cert_user_id(cert: &openpgp::Cert) -> Option<String> {
    cert.userids()
        .next()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
}

/// Encrypt a message to one or more recipient certificates.
pub fn encrypt_message(plaintext: &[u8], recipients: &[&openpgp::Cert]) -> HbResult<Vec<u8>> {
    let mut output = Vec::new();

    let mut recipient_kas = Vec::new();
    for cert in recipients {
        for ka in cert
            .keys()
            .with_policy(POLICY, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .chain(
                cert.keys()
                    .with_policy(POLICY, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .for_storage_encryption(),
            )
        {
            recipient_kas.push(ka);
        }
    }

    if recipient_kas.is_empty() {
        return Err(HbError::OpenPgp(
            "No valid encryption-capable keys found in recipients".into(),
        ));
    }

    let recipients_refs: Vec<openpgp::serialize::stream::Recipient> =
        recipient_kas.into_iter().map(Into::into).collect();

    {
        let message = Message::new(&mut output);
        let armorer = Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| HbError::OpenPgp(format!("Armorer: {e}")))?;
        let encryptor = Encryptor::for_recipients(armorer, recipients_refs)
            .build()
            .map_err(|e| HbError::OpenPgp(format!("Encryptor: {e}")))?;
        let mut literal = LiteralWriter::new(encryptor)
            .build()
            .map_err(|e| HbError::OpenPgp(format!("LiteralWriter: {e}")))?;
        literal
            .write_all(plaintext)
            .map_err(|e| HbError::OpenPgp(format!("Write: {e}")))?;
        literal
            .finalize()
            .map_err(|e| HbError::OpenPgp(format!("Finalize: {e}")))?;
    }

    Ok(output)
}

/// Helper for PGP decryption.
struct DecryptHelper {
    secret_keys: Vec<openpgp::Cert>,
}

impl VerificationHelper for DecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new()) // We don't verify signatures during decryption for now
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptHelper {
    fn get_secret_keys_for(
        &self,
        pkesks: &[openpgp::packet::PKESK],
    ) -> Vec<(openpgp::packet::PKESK, KeyPair)> {
        let mut result = Vec::new();
        for pkesk in pkesks {
            for cert in &self.secret_keys {
                for key in cert
                    .keys()
                    .with_policy(POLICY, None)
                    .supported()
                    .unencrypted_secret()
                    .for_transport_encryption()
                    .chain(
                        cert.keys()
                            .with_policy(POLICY, None)
                            .supported()
                            .unencrypted_secret()
                            .for_storage_encryption(),
                    )
                {
                    if let Ok(pair) = key.key().clone().into_keypair() {
                        result.push((pkesk.clone(), pair));
                    }
                }
            }
        }
        result
    }
}

impl DecryptionHelper for DecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        for (pkesk, mut pair) in self.get_secret_keys_for(pkesks) {
            if pkesk
                .decrypt(&mut pair, sym_algo)
                .map(|(algo, session_key)| decrypt(algo, &session_key))
                .unwrap_or(false)
            {
                return Ok(None);
            }
        }
        Err(openpgp::Error::ManipulatedMessage.into())
    }
}

/// Decrypt a PGP message.
pub fn decrypt_message(ciphertext: &[u8], secret_certs: &[openpgp::Cert]) -> HbResult<Vec<u8>> {
    let helper = DecryptHelper {
        secret_keys: secret_certs.to_vec(),
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| HbError::OpenPgp(format!("DecryptorBuilder: {e}")))?
        .with_policy(POLICY, None, helper)
        .map_err(|e| HbError::OpenPgp(format!("Decryptor: {e}")))?;

    let mut output = Vec::new();
    decryptor
        .read_to_end(&mut output)
        .map_err(|e| HbError::OpenPgp(format!("Read decrypted: {e}")))?;

    Ok(output)
}

/// Sign a message using a PGP certificate.
pub fn sign_message(message: &[u8], signer_cert: &openpgp::Cert) -> HbResult<Vec<u8>> {
    let signing_ka = signer_cert
        .keys()
        .with_policy(POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .unencrypted_secret()
        .next()
        .ok_or_else(|| HbError::OpenPgp("No signing key found".into()))?;

    let keypair = signing_ka
        .key()
        .clone()
        .into_keypair()
        .map_err(|e| HbError::OpenPgp(format!("Keypair: {e}")))?;

    let mut output = Vec::new();
    {
        let message_writer = Message::new(&mut output);
        let armorer = Armorer::new(message_writer)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| HbError::OpenPgp(format!("Armorer: {e}")))?;
        let signer = Signer::new(armorer, keypair)
            .map_err(|e| HbError::OpenPgp(format!("Signer init: {e}")))?
            .build()
            .map_err(|e| HbError::OpenPgp(format!("Signer: {e}")))?;
        let mut literal = LiteralWriter::new(signer)
            .build()
            .map_err(|e| HbError::OpenPgp(format!("LiteralWriter: {e}")))?;
        literal
            .write_all(message)
            .map_err(|e| HbError::OpenPgp(format!("Write: {e}")))?;
        literal
            .finalize()
            .map_err(|e| HbError::OpenPgp(format!("Finalize: {e}")))?;
    }
    Ok(output)
}

/// Helper for PGP signature verification.
struct VerificationHelperImpl {
    signer_certs: Vec<openpgp::Cert>,
    verified: bool,
}

impl VerificationHelper for VerificationHelperImpl {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.signer_certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    if result.is_ok() {
                        self.verified = true;
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Verify a signed PGP message.
/// Returns (message_content, is_valid).
pub fn verify_message(
    signed_message: &[u8],
    signer_certs: &[openpgp::Cert],
) -> HbResult<(Vec<u8>, bool)> {
    let helper = VerificationHelperImpl {
        signer_certs: signer_certs.to_vec(),
        verified: false,
    };

    let mut verifier = VerifierBuilder::from_bytes(signed_message)
        .map_err(|e| HbError::OpenPgp(format!("VerifierBuilder: {e}")))?
        .with_policy(POLICY, None, helper)
        .map_err(|e| HbError::OpenPgp(format!("Verifier: {e}")))?;

    let mut content = Vec::new();
    verifier
        .read_to_end(&mut content)
        .map_err(|e| HbError::OpenPgp(format!("Read: {e}")))?;

    let verified = verifier.into_helper().verified;
    Ok((content, verified))
}

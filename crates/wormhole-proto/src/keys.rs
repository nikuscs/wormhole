//! Ed25519 identities, authorized public keys, and challenge transcripts.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use camino::Utf8Path;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nix::{
    errno::Errno,
    fcntl::{AtFlags, OFlag, open, openat, renameat},
    sys::stat::{Mode, SFlag, fstatat, mkdirat},
    unistd::{UnlinkatFlags, unlinkat},
};
use sha2::{Digest, Sha256};

use crate::error::ProtoError;

const PRIVATE_PREFIX: &str = "wormhole-ed25519";
const CHALLENGE_CONTEXT: &[u8] = b"wormhole-v1-challenge";
const PRIVATE_MODE: u16 = 0o600;
const DIRECTORY_MODE: u16 = 0o700;
const KEY_BYTES: usize = 32;
const MAX_IDENTITY_FILE_BYTES: usize = 1024;
const DIRECTORY_FLAGS: OFlag = OFlag::O_RDONLY.union(OFlag::O_DIRECTORY).union(OFlag::O_NOFOLLOW);

/// An Ed25519 client identity whose secret seed is zeroized on drop by `SigningKey`.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generates a cryptographically random identity.
    pub fn generate() -> Self {
        Self { signing: SigningKey::generate(&mut rand::rng()) }
    }

    /// Loads a private identity without following any symbolic-link path component.
    pub fn load(path: &Utf8Path) -> Result<Self, ProtoError> {
        let (parent, file_name) = open_parent_directory(path, false)?;
        let descriptor = openat(
            &parent,
            file_name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| map_path_error(path, error))?;
        let mut file = File::from(descriptor);
        validate_identity_file(path, &file.metadata()?)?;
        let mut encoded = String::new();
        (&mut file).take((MAX_IDENTITY_FILE_BYTES + 1) as u64).read_to_string(&mut encoded)?;
        if encoded.len() > MAX_IDENTITY_FILE_BYTES {
            return Err(identity_file_error("identity file is too large"));
        }
        parse_private(&encoded)
    }

    /// Atomically stores a private identity without following symbolic links.
    pub fn save(&self, path: &Utf8Path) -> Result<(), ProtoError> {
        let (parent, file_name) = open_parent_directory(path, true)?;
        reject_final_symlink(path, &parent, &file_name)?;
        let temporary = temporary_name(&file_name);
        let result = self.write_and_replace(path, &parent, &temporary, &file_name);
        if result.is_err() {
            let _ignored = unlinkat(&parent, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
        }
        result
    }

    /// Returns the RFC 4648 padded base64 public key.
    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().as_bytes())
    }

    /// Returns the stable SHA-256 public-key fingerprint.
    pub fn fingerprint(&self) -> String {
        fingerprint_bytes(self.signing.verifying_key().as_bytes())
    }

    /// Signs the canonical relay challenge transcript and returns padded base64.
    pub fn sign_challenge(&self, nonce: &[u8; KEY_BYTES], server: &str, proto: u16) -> String {
        let signature = self.signing.sign(&challenge_transcript(nonce, server, proto));
        STANDARD.encode(signature.to_bytes())
    }

    fn write_and_replace(
        &self,
        path: &Utf8Path,
        parent: &File,
        temporary: &str,
        destination: &str,
    ) -> Result<(), ProtoError> {
        let descriptor = openat(
            parent,
            temporary,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(PRIVATE_MODE),
        )
        .map_err(|error| map_path_error(path, error))?;
        let mut file = File::from(descriptor);
        writeln!(file, "{PRIVATE_PREFIX} {}", private_base64(&self.signing))?;
        file.flush()?;
        file.sync_all()?;
        renameat(parent, temporary, parent, destination)
            .map_err(|error| map_path_error(path, error))?;
        parent.sync_all()?;
        Ok(())
    }
}

/// A validated authorized-keys entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRef {
    encoded: String,
    comment: Option<String>,
}

impl PublicKeyRef {
    /// Parses `<padded-public-key-base64> <optional comment>`.
    pub fn parse(line: &str) -> Result<Self, ProtoError> {
        let line = line.trim();
        let split_at = line.find(char::is_whitespace).unwrap_or(line.len());
        let (encoded, remainder) = line.split_at(split_at);
        decode_verifying_key(encoded)?;
        let comment =
            if remainder.trim().is_empty() { None } else { Some(remainder.trim().to_owned()) };
        Ok(Self { encoded: encoded.to_owned(), comment })
    }

    /// Returns the padded base64 public key.
    pub fn as_base64(&self) -> &str {
        &self.encoded
    }

    /// Returns the optional administrator comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Returns the stable SHA-256 public-key fingerprint.
    pub fn fingerprint(&self) -> String {
        let verifying = decode_verifying_key(&self.encoded).expect("validated public key");
        fingerprint_bytes(verifying.as_bytes())
    }
}

/// Verifies a canonical relay challenge signature using strict Ed25519 validation.
pub fn verify_challenge(
    public_base64: &str,
    nonce: &[u8; KEY_BYTES],
    server: &str,
    proto: u16,
    signature_base64: &str,
) -> bool {
    let Ok(verifying) = decode_verifying_key(public_base64) else {
        return false;
    };
    let Ok(signature_bytes) = decode_array::<64>(signature_base64) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying.verify_strict(&challenge_transcript(nonce, server, proto), &signature).is_ok()
}

fn challenge_transcript(nonce: &[u8; KEY_BYTES], server: &str, proto: u16) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(CHALLENGE_CONTEXT.len() + nonce.len() + server.len() + 10);
    transcript.extend_from_slice(CHALLENGE_CONTEXT);
    append_length_prefixed(&mut transcript, nonce);
    append_length_prefixed(&mut transcript, server.as_bytes());
    transcript.extend_from_slice(&proto.to_le_bytes());
    transcript
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("challenge component length fits u32");
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
}

fn private_base64(signing: &SigningKey) -> String {
    STANDARD.encode(signing.to_bytes())
}

fn fingerprint_bytes(public: &[u8; KEY_BYTES]) -> String {
    format!("WH256:{}", STANDARD.encode(Sha256::digest(public)))
}

fn parse_private(contents: &str) -> Result<Identity, ProtoError> {
    let mut lines = contents.lines();
    let line = lines
        .next()
        .ok_or_else(|| ProtoError::InvalidIdentity("identity file is empty".to_owned()))?;
    if lines.next().is_some() {
        return Err(ProtoError::InvalidIdentity("identity file must contain one line".to_owned()));
    }
    let mut fields = line.split_whitespace();
    if fields.next() != Some(PRIVATE_PREFIX) {
        return Err(ProtoError::InvalidIdentity("unsupported identity format".to_owned()));
    }
    let seed = fields
        .next()
        .ok_or_else(|| ProtoError::InvalidIdentity("identity seed is missing".to_owned()))?;
    if fields.next().is_some() {
        return Err(ProtoError::InvalidIdentity("unexpected identity fields".to_owned()));
    }
    Ok(Identity { signing: SigningKey::from_bytes(&decode_array(seed)?) })
}

pub(crate) fn decode_nonce(encoded: &str) -> Result<[u8; KEY_BYTES], ProtoError> {
    decode_array(encoded)
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, ProtoError> {
    let public = decode_array(encoded)?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|error| ProtoError::InvalidIdentity(format!("invalid public key: {error}")))?;
    if verifying.is_weak() {
        return Err(ProtoError::InvalidIdentity("weak public keys are forbidden".to_owned()));
    }
    Ok(verifying)
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], ProtoError> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|error| ProtoError::InvalidIdentity(format!("invalid padded base64: {error}")))?;
    decoded.try_into().map_err(|value: Vec<u8>| {
        ProtoError::InvalidIdentity(format!("expected {N} decoded bytes, got {}", value.len()))
    })
}

fn open_parent_directory(path: &Utf8Path, create: bool) -> Result<(File, String), ProtoError> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ProtoError::InvalidIdentity(format!("identity path has no file name: {path}"))
        })?
        .to_owned();
    let traversal = traversal_path(path);
    let start = if traversal.is_absolute() { "/" } else { "." };
    let descriptor =
        open(start, DIRECTORY_FLAGS, Mode::empty()).map_err(|error| map_path_error(path, error))?;
    let mut directory = File::from(descriptor);
    let parent = traversal.parent().unwrap_or_else(|| std::path::Path::new(""));
    for component in parent.components() {
        directory = descend_directory(path, directory, component, create)?;
    }
    Ok((directory, file_name))
}

fn traversal_path(path: &Utf8Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    for (alias, target) in
        [("/var", "/private/var"), ("/tmp", "/private/tmp"), ("/etc", "/private/etc")]
    {
        if let Ok(remainder) = path.strip_prefix(alias) {
            return std::path::Path::new(target).join(remainder.as_std_path());
        }
    }
    path.as_std_path().to_path_buf()
}

fn descend_directory(
    full_path: &Utf8Path,
    directory: File,
    component: Component<'_>,
    create: bool,
) -> Result<File, ProtoError> {
    let name = match component {
        Component::RootDir | Component::CurDir => return Ok(directory),
        Component::ParentDir => OsStr::new(".."),
        Component::Normal(name) => name,
        Component::Prefix(_) => {
            return Err(ProtoError::InvalidIdentity(format!(
                "unsupported identity path: {full_path}"
            )));
        }
    };
    match openat(&directory, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(descriptor) => Ok(File::from(descriptor)),
        Err(Errno::ENOENT) if create => {
            match mkdirat(&directory, name, Mode::from_bits_truncate(DIRECTORY_MODE)) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(error) => return Err(map_path_error(full_path, error)),
            }
            let descriptor = openat(&directory, name, DIRECTORY_FLAGS, Mode::empty())
                .map_err(|error| map_path_error(full_path, error))?;
            Ok(File::from(descriptor))
        }
        Err(error) => Err(map_path_error(full_path, error)),
    }
}

fn reject_final_symlink(path: &Utf8Path, parent: &File, file_name: &str) -> Result<(), ProtoError> {
    match fstatat(parent, file_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFLNK) => {
            Err(ProtoError::KeySymlink(path.to_string()))
        }
        Ok(_) | Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(map_path_error(path, error)),
    }
}

fn map_path_error(path: &Utf8Path, error: Errno) -> ProtoError {
    if matches!(error, Errno::ELOOP | Errno::ENOTDIR) {
        ProtoError::KeySymlink(path.to_string())
    } else {
        ProtoError::Io(io::Error::from_raw_os_error(error as i32))
    }
}

fn validate_identity_file(path: &Utf8Path, metadata: &fs::Metadata) -> Result<(), ProtoError> {
    if !metadata.is_file() {
        return Err(identity_file_error("identity path is not a regular file"));
    }
    if metadata.len() > MAX_IDENTITY_FILE_BYTES as u64 {
        return Err(identity_file_error("identity file is too large"));
    }
    let mode = metadata.mode() & 0o777;
    if mode != u32::from(PRIVATE_MODE) {
        return Err(ProtoError::KeyPermissions { path: path.to_string(), mode });
    }
    Ok(())
}

fn identity_file_error(message: &str) -> ProtoError {
    ProtoError::InvalidIdentity(message.to_owned())
}

fn temporary_name(file_name: &str) -> String {
    format!(".{file_name}.{:016x}.tmp", rand::random::<u64>())
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;

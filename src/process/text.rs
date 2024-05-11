use super::process_genpass;
use crate::{cli::TextSignFormat, get_reader};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::string::FromUtf8Error;
use std::{fs, io::Read, path::Path};
pub trait TextSign {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerify {
    //sign the data from the reader and return the signature
    fn verify(&self, reader: impl Read, sig: &[u8]) -> Result<bool>;
}

pub trait TextEncrypt {
    fn encrypt(&self, buf: &[u8]) -> Result<String>;
}

pub trait TextDecrypt {
    fn decrypt(&self, buf: &[u8]) -> Result<String>;
}

pub struct Blake3 {
    key: [u8; 32],
}
pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct ChaCha20Poly1305Cipher {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}
pub trait NonceLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}
pub trait KeyGenerator {
    fn generate() -> Result<Vec<Vec<u8>>>;
}

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut reader: Box<dyn Read> = get_reader(input)?;

    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
    };

    let signed = URL_SAFE_NO_PAD.encode(signed);
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    sig: &str,
    format: TextSignFormat,
) -> Result<bool> {
    let mut reader: Box<dyn Read> = get_reader(input)?;
    let sig = URL_SAFE_NO_PAD.decode(sig)?;

    let verified = match format {
        TextSignFormat::Blake3 => {
            let verifier = Blake3::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
        TextSignFormat::Ed25519 => {
            let verifier = Ed25519Verifier::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
    };

    Ok(verified)
}

pub fn process_text_generate(format: TextSignFormat) -> Result<Vec<Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub fn process_text_encrypt(input: &str, key: &str) -> Result<String> {
    let mut reader: Box<dyn Read> = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    //remove the "\n" from the buffer if any
    buf.retain(|&x| x != b'\n');

    let cipher = ChaCha20Poly1305Cipher::load(key)?;
    cipher.encrypt(&buf)
}

pub fn process_text_decrypt(input: &str, key: &str) -> Result<String> {
    let mut reader: Box<dyn Read> = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    buf.retain(|&x| x != b'\n');

    let cipher = ChaCha20Poly1305Cipher::load(key)?;
    cipher.decrypt(&buf)
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();
        //println!("new sig: {}", URL_SAFE_NO_PAD.encode(&hash));
        Ok(hash == sig)
    }
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = self.key.sign(&buf);
        Ok(sig.to_bytes().to_vec())
    }
}

impl TextVerify for Ed25519Verifier {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = ed25519_dalek::Signature::from_bytes(sig.try_into()?);
        Ok(self.key.verify(&buf, &sig).is_ok())
    }
}

impl TextEncrypt for ChaCha20Poly1305Cipher {
    fn encrypt(&self, buf: &[u8]) -> Result<String> {
        let key = Key::from_slice(&self.key);
        let nonce = Nonce::from_slice(&self.nonce);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphered = cipher
            .encrypt(nonce, buf.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?; // Convert encryption error to anyhow::Error

        let ciphertext = URL_SAFE_NO_PAD.encode(ciphered);
        Ok(ciphertext)
    }
}

impl TextDecrypt for ChaCha20Poly1305Cipher {
    fn decrypt(&self, buf: &[u8]) -> Result<String> {
        // Create the key and nonce slices
        let key = Key::from_slice(&self.key);
        let nonce = Nonce::from_slice(&self.nonce);

        // Create a new cipher instance
        let cipher = ChaCha20Poly1305::new(key);

        // Decode the input ciphertext from base64, handling decode errors
        let ciphered = URL_SAFE_NO_PAD
            .decode(buf.as_ref())
            .map_err(|e: DecodeError| anyhow!("Base64 decoding failed: {:?}", e))?;

        // Decrypt data using the cipher, handling decryption errors
        let plaintext_bytes = cipher
            .decrypt(nonce, ciphered.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        // Convert decrypted bytes to a UTF-8 string, handling encoding errors
        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|e: FromUtf8Error| anyhow!("UTF-8 conversion failed: {:?}", e))?;

        Ok(plaintext)
    }
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            anyhow::bail!("Invalid key length");
        }
        let mut k = [0; 32];
        k.copy_from_slice(key);
        Ok(Self::new(k))
    }
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = SigningKey::from_bytes(key.try_into()?);
        Ok(Self::new(key))
    }
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(key.try_into().unwrap())
            .map_err(|_| anyhow::anyhow!("Failed to convert key"))?;
        Ok(Self::new(key))
    }
}

impl ChaCha20Poly1305Cipher {
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self { key, nonce }
    }

    pub fn try_new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        if key.len() != 32 || nonce.len() != 12 {
            anyhow::bail!("Invalid key length");
        }
        let mut k = [0; 32];
        k.copy_from_slice(key);
        let mut n = [0; 12];
        n.copy_from_slice(nonce);

        Ok(Self::new(k, n))
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        //read the key string from the file without "\n" convert it to Vec
        let key = fs::read(path)?;
        let key = key.split(|&x| x == b'\n').collect::<Vec<_>>()[0];
        Self::try_new(key)
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        let key = key.split(|&x| x == b'\n').collect::<Vec<_>>()[0];
        Self::try_new(key)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        let key = key.split(|&x| x == b'\n').collect::<Vec<_>>()[0];
        Self::try_new(key)
    }
}

impl KeyLoader for ChaCha20Poly1305Cipher {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = path.as_ref().to_path_buf().join("key.txt");
        let nonce = path.as_ref().to_path_buf().join("nonce.txt");

        let key = fs::read(key)?;
        let key = key.split(|&x| x == b'\n').collect::<Vec<_>>()[0];

        let nonce = fs::read(nonce)?;
        let nonce = nonce.split(|&x| x == b'\n').collect::<Vec<_>>()[0];

        Self::try_new(key, nonce)
    }
}

impl KeyGenerator for Blake3 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        Ok(vec![key.as_bytes().to_vec()])
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.to_bytes().to_vec();
        Ok(vec![sk, pk])
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;

    #[test]
    fn test_blake3_sign_verify() -> Result<()> {
        let key = [0; 32];
        let signer = Blake3::new(key);
        let verifier = Blake3::new(key);

        let data = b"hello world";
        let sig = signer.sign(&mut &data[..])?;
        assert!(verifier.verify(&mut &data[..], &sig)?);

        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify() -> Result<()> {
        let sk = Ed25519Signer::load("assets/fixtures/ed25519.sk")?;
        let pk = Ed25519Verifier::load("assets/fixtures/ed25519.pk")?;

        let data = b"hello world";
        let sig = sk.sign(&mut &data[..])?;
        assert!(pk.verify(&mut &data[..], &sig)?);
        Ok(())
    }
}

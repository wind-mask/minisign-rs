use std::fmt::Display;

use crate::{
    errors::Result, signature::Signature, SError, ALG_SIZE, COMPONENT_SIZE, KEY_SIG_ALG, KID_SIZE,
};
use base64::Engine;
use ed25519_dalek::ed25519::{self, ComponentBytes};
/// A `PublicKeyBox` represents a minisign public key.
///
/// also can be output to a string and parse from a str.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyBox<'s> {
    pub(crate) untrusted_comment: Option<&'s str>,
    pub(crate) public_key: PublicKey,
}

impl<'s> PublicKeyBox<'s> {
    pub(crate) fn new(untrusted_comment: Option<&'s str>, public_key: PublicKey) -> Self {
        Self {
            untrusted_comment,
            public_key,
        }
    }
    pub fn from_verifying_key(
        key: ed25519_dalek::VerifyingKey,
        key_id: &[u8; 8],
        untrusted_comment: Option<&'s str>,
    ) -> Result<Self> {
        let pk = RawPk::new(key.to_bytes());
        let public_key = PublicKey::new(KEY_SIG_ALG, *key_id, pk);
        Ok(Self::new(untrusted_comment, public_key))
    }
    /// Parse a `PublicKeyBox` from str.
    ///
    /// as it store in a file.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &'s str) -> Result<Self> {
        parse_public_key(s)
    }
    /// Get the untrusted comment.
    pub fn untrusted_comment(&self) -> Option<&'s str> {
        self.untrusted_comment
    }
    pub(crate) fn verify(
        &self,
        msg: &[u8],
        sig: &Signature,
        trusted_comment: Option<&str>,
    ) -> Result<bool> {
        if !(self.public_key.key.verify(msg, &sig.sig)?) {
            return Err(SError::new(
                crate::ErrorKind::PublicKey,
                "verify sig failed",
            ));
        }
        let mut global_data = vec![];
        global_data.extend_from_slice(&sig.sig.to_bytes());
        global_data.extend_from_slice(trusted_comment.unwrap_or("").as_bytes());
        if !(self.public_key.key.verify(&global_data, &sig.global_sig)?) {
            return Err(SError::new(
                crate::ErrorKind::PublicKey,
                "verify global sig failed",
            ));
        }
        Ok(true)
    }
    pub(crate) fn self_verify(&self) -> Result<bool> {
        if self.public_key.sig_alg != KEY_SIG_ALG {
            return Err(SError::new(
                crate::ErrorKind::PublicKey,
                "invalid public key signature algorithm",
            ));
        }
        Ok(true)
    }
}
impl Display for PublicKeyBox<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str("untrusted comment: ");
        if let Some(c) = self.untrusted_comment {
            s.push_str(c);
        }
        s.push('\n');
        let encoder = base64::engine::general_purpose::STANDARD;
        let mut pk_format = vec![];
        pk_format.extend_from_slice(&self.public_key.sig_alg);
        pk_format.extend_from_slice(&self.public_key.key_id);
        pk_format.extend_from_slice(&self.public_key.key.0);
        let pk = encoder.encode(&pk_format);
        s.push_str(&pk);
        s.push('\n');
        write!(f, "{}", s)
    }
}
fn parse_public_key(s: &str) -> Result<PublicKeyBox> {
    let mut lines = s.lines();
    if let Some(c) = lines.next() {
        let untrusted_comment = c.strip_prefix("untrusted comment: ");
        let public_key = lines
            .next()
            .ok_or_else(|| SError::new(crate::ErrorKind::PublicKey, "missing public key"))?;
        let decoder = base64::engine::general_purpose::STANDARD;
        let pk_format = decoder
            .decode(public_key.as_bytes())
            .map_err(|e| SError::new(crate::ErrorKind::PublicKey, e))?;
        if pk_format.len() != ALG_SIZE + KID_SIZE + COMPONENT_SIZE {
            return Err(SError::new(
                crate::ErrorKind::PublicKey,
                "invalid public key length",
            ));
        }
        let pk_sig_alg = &pk_format[..ALG_SIZE];
        let pk_key_id = &pk_format[ALG_SIZE..ALG_SIZE + KID_SIZE];
        let pk_key = &pk_format[ALG_SIZE + KID_SIZE..];
        let pk = RawPk::new(pk_key.try_into().unwrap());
        let public_key = PublicKey::new(
            pk_sig_alg.try_into().unwrap(),
            pk_key_id.try_into().unwrap(),
            pk,
        );
        Ok(PublicKeyBox::new(untrusted_comment, public_key))
    } else {
        Err(SError::new(crate::ErrorKind::PublicKey, "empty public key"))
    }
}
#[cfg(test)]
#[test]
fn test_parse_public_key() {
    use crate::KeyPairBox;
    let password = b"password";
    let k = KeyPairBox::generate(Some(password), None, None).unwrap();
    let file = k.public_key_box.to_string();
    let pk = parse_public_key(&file).unwrap();
    assert_eq!(file, pk.to_string());
}
/// A `PublicKey` is used to verify signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicKey {
    pub sig_alg: [u8; 2],
    pub key_id: [u8; 8],
    pub key: RawPk,
}
impl PublicKey {
    pub fn new(sig_alg: [u8; 2], key_id: [u8; 8], key: RawPk) -> Self {
        Self {
            sig_alg,
            key_id,
            key,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawPk(pub ComponentBytes);
impl RawPk {
    pub fn new(key: ComponentBytes) -> Self {
        Self(key)
    }
    pub fn verify(&self, msg: &[u8], sig: &ed25519::Signature) -> Result<bool> {
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&self.0)?;
        Ok(pk.verify_strict(msg, sig).map(|_| true)?)
    }
}

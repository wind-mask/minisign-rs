use std::fmt::Display;
use std::vec;

use base64::Engine;
use ed25519_dalek::ed25519;

use crate::errors::Result;
use crate::{SError, ALG_SIZE, KID_SIZE, SIGALG_PREHASHED, SIG_SIZE};
/// A `SignatureBox` represents a minisign signature.
///
/// also can be output to a string and parse from a str.
///
/// # Security
///
/// This does not mean trusted_comment is verified.
/// must verify the signature by `PublicKeyBox`.
#[derive(Debug, Clone)]
pub struct SignatureBox<'s> {
    pub(crate) untrusted_comment: Option<&'s str>,
    pub(crate) trusted_comment: Option<&'s str>,
    pub(crate) signature: Signature,
}
fn parse_signature(s: &str) -> Result<SignatureBox> {
    let mut lines = s.lines();
    let untrusted_comment = if let Some(c) = lines.next() {
        if let Some(uc) = c.strip_prefix("untrusted comment: ") {
            Some(uc)
        } else {
            return Err(SError::new(
                crate::ErrorKind::SignatureError,
                "missing untrusted comment",
            ));
        }
    } else {
        None
    };
    let sig = lines
        .next()
        .ok_or_else(|| SError::new(crate::ErrorKind::SignatureError, "missing signature"))?;
    let decoder = base64::engine::general_purpose::STANDARD;
    let sig_format = decoder
        .decode(sig.as_bytes())
        .map_err(|e| SError::new(crate::ErrorKind::SignatureError, e))?;
    if sig_format.len() != ALG_SIZE + KID_SIZE + SIG_SIZE {
        return Err(SError::new(
            crate::ErrorKind::SignatureError,
            "invalid signature length",
        ));
    }
    let sig_alg = &sig_format[..ALG_SIZE];
    let key_id = &sig_format[ALG_SIZE..ALG_SIZE + KID_SIZE];
    let sig = &sig_format[ALG_SIZE + KID_SIZE..];
    let trusted_comment = if let Some(c) = lines.next() {
        if let Some(tc) = c.strip_prefix("trusted comment: ") {
            Some(tc)
        } else {
            return Err(SError::new(
                crate::ErrorKind::SignatureError,
                "missing trusted comment",
            ));
        }
    } else {
        return Err(SError::new(
            crate::ErrorKind::SignatureError,
            "missing trusted comment",
        ));
    };
    let global_sig = lines
        .next()
        .ok_or_else(|| SError::new(crate::ErrorKind::SignatureError, "missing global signature"))?;
    let global_sig_format = decoder
        .decode(global_sig.as_bytes())
        .map_err(|e| SError::new(crate::ErrorKind::SignatureError, e))?;
    if global_sig_format.len() != 64 {
        return Err(SError::new(
            crate::ErrorKind::SignatureError,
            "invalid global signature length",
        ));
    }
    Ok(SignatureBox::new(
        untrusted_comment,
        trusted_comment,
        Signature::new(
            sig_alg.try_into().unwrap(),
            key_id.try_into().unwrap(),
            sig.try_into().unwrap(),
            ed25519::Signature::from_bytes(&global_sig_format.try_into().unwrap()),
        ),
    ))
}

#[cfg(test)]
#[test]
fn test_parse_signature() {
    use crate::{sign, KeyPairBox};

    let password = b"password";
    let k = KeyPairBox::generate(Some(password), None, None).unwrap();
    let file = sign(
        Some(&k.public_key_box),
        &k.secret_key_box,
        Some(password),
        "test".as_bytes(),
        Some("trusted comment"),
        Some("untrusted comment"),
    )
    .unwrap()
    .to_string();
    let sig = parse_signature(&file).unwrap();
    assert_eq!(file, sig.to_string());
}
impl Display for SignatureBox<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str("untrusted comment: ");
        if let Some(c) = self.untrusted_comment {
            s.push_str(c);
        }
        s.push('\n');
        let encoder = base64::engine::general_purpose::STANDARD;
        let mut sig_format = vec![];
        sig_format.extend_from_slice(&self.signature.sig_alg);
        sig_format.extend_from_slice(&self.signature.key_id);
        sig_format.extend_from_slice(&self.signature.sig.to_bytes());
        let sig = encoder.encode(&sig_format);
        s.push_str(&sig);
        s.push('\n');
        s.push_str("trusted comment: ");
        if let Some(c) = self.trusted_comment {
            s.push_str(c);
        }
        s.push('\n');
        let global_sig = encoder.encode(self.signature.global_sig.to_bytes());
        s.push_str(&global_sig);
        s.push('\n');
        write!(f, "{}", s)
    }
}

impl<'s> SignatureBox<'s> {
    pub(crate) fn new(
        untrusted_comment: Option<&'s str>,
        trusted_comment: Option<&'s str>,
        signature: Signature,
    ) -> Self {
        Self {
            untrusted_comment,
            trusted_comment,
            signature,
        }
    }
    pub fn is_prehashed(&self) -> bool {
        self.signature.sig_alg == SIGALG_PREHASHED
    }
    pub fn untrusted_comment(&self) -> Option<&'s str> {
        self.untrusted_comment
    }
    pub fn trusted_comment(&self) -> Option<&'s str> {
        self.trusted_comment
    }
    pub fn key_id(&self) -> &[u8; KID_SIZE] {
        &self.signature.key_id
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<SignatureBox> {
        parse_signature(s)
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Signature {
    pub sig_alg: [u8; ALG_SIZE],
    pub key_id: [u8; KID_SIZE],
    pub sig: ed25519::Signature,
    pub global_sig: ed25519::Signature,
}
impl Signature {
    pub fn new(
        sig_alg: [u8; ALG_SIZE],
        key_id: [u8; KID_SIZE],
        sig: ed25519::Signature,
        global_sig: ed25519::Signature,
    ) -> Self {
        Self {
            sig_alg,
            key_id,
            sig,
            global_sig,
        }
    }
}

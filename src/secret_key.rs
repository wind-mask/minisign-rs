use std::fmt::Display;

use crate::{
    util::raw_scrypt_params, Result, SError, ALG_SIZE, CHK_ALG, CHK_SIZE, COMPONENT_SIZE, KDF_ALG,
    KDF_LIMIT_SIZE, KDF_SALT_SIZE, KEYNUM_SK_SIZE, KEY_SIG_ALG, KID_SIZE, MEMLIMIT, N_LOG2_MAX,
    OPSLIMIT,
};
use base64::Engine;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{
    ed25519::{self, ComponentBytes},
    Signer,
};
use scrypt::password_hash::rand_core::{self, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A `SecretKeyBox` represents a minisign secret key.
///
/// also can be output to a string and parse from a str.
#[derive(Debug, Clone)]
pub struct SecretKeyBox<'s> {
    pub(crate) untrusted_comment: Option<&'s str>,
    pub(crate) secret_key: SecretKey,
}
impl Display for SecretKeyBox<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str("untrusted comment: ");
        if let Some(c) = self.untrusted_comment {
            s.push_str(c);
        }
        s.push('\n');
        let encoder = base64::engine::general_purpose::STANDARD;
        let mut sk_format = vec![];
        sk_format.extend_from_slice(&self.secret_key.sig_alg);
        sk_format.extend_from_slice(&self.secret_key.kdf_alg);
        sk_format.extend_from_slice(&self.secret_key.cksum_alg);
        sk_format.extend_from_slice(&self.secret_key.kdf_salt);
        sk_format.extend_from_slice(&self.secret_key.kdf_opslimit.to_le_bytes());
        sk_format.extend_from_slice(&self.secret_key.kdf_memlimit.to_le_bytes());
        sk_format.extend_from_slice(&self.secret_key.keynum_sk);
        let sk = encoder.encode(&sk_format);
        s.push_str(&sk);
        s.push('\n');

        write!(f, "{}", s)
    }
}
type Blake2b256 = Blake2b<blake2::digest::consts::U32>;
impl<'s> SecretKeyBox<'s> {
    fn new(untrusted_comment: Option<&'s str>, secret_key: SecretKey) -> Self {
        Self {
            untrusted_comment,
            secret_key,
        }
    }
    pub fn from_signing_key(
        signing_key: ed25519_dalek::SigningKey,
        kid: &[u8; KID_SIZE],
        password: Option<&[u8]>,
        untrusted_comment: Option<&'s str>,
    ) -> Result<Self> {
        let sk = signing_key.to_bytes();
        let pk = signing_key.verifying_key().to_bytes();
        let mut dest = [0u8; KDF_SALT_SIZE];
        rand_core::OsRng.try_fill_bytes(&mut dest)?;

        let mut hash = Blake2b256::new();
        hash.update(KEY_SIG_ALG);
        hash.update(kid);
        hash.update(sk);
        hash.update(pk);
        let mut kdf_buf = kdf(password, &dest, OPSLIMIT, MEMLIMIT)?;
        let keynum_sk = KeynumSK {
            key_id: *kid,
            sec_key: RawSk(sk),
            pub_key: pk,
            checksum: hash.finalize().to_vec().try_into().unwrap(),
        };
        kdf_buf = keynum_sk.to_bytes(kdf_buf);
        let secret_key = SecretKey {
            sig_alg: KEY_SIG_ALG,
            kdf_alg: KDF_ALG,
            cksum_alg: CHK_ALG,
            kdf_salt: dest,
            kdf_opslimit: OPSLIMIT,
            kdf_memlimit: MEMLIMIT,
            keynum_sk: kdf_buf,
        };

        Ok(Self::new(untrusted_comment, secret_key))
    }
    pub(crate) fn sign(
        &self,
        message: &[u8],
        password: Option<&[u8]>,
    ) -> Result<ed25519::Signature> {
        self.secret_key.sign(message, password)
    }
    pub(crate) fn xor_keynum_sk(&self, password: Option<&[u8]>) -> Result<KeynumSK> {
        self.secret_key.xor_keynum_sk(password)
    }
    /// Parse a `SecretKeyBox` from str.
    ///
    /// as it store in a file.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &'s str) -> Result<Self> {
        parse_secret_key(s)
    }
    /// Get the untrusted comment.
    pub fn untrusted_comment(&self) -> Option<&'s str> {
        self.untrusted_comment
    }
}
fn parse_secret_key(s: &str) -> Result<SecretKeyBox> {
    let mut lines = s.lines();
    if let Some(c) = lines.next() {
        let untrusted_comment = c.strip_prefix("untrusted comment: ");
        let secret_key = lines
            .next()
            .ok_or_else(|| SError::new(crate::ErrorKind::SecretKey, "missing secret key"))?;
        let decoder = base64::engine::general_purpose::STANDARD;
        let sk_format = decoder
            .decode(secret_key.as_bytes())
            .map_err(|e| SError::new(crate::ErrorKind::SecretKey, e))?;
        if sk_format.len()
            != ALG_SIZE
                + ALG_SIZE
                + ALG_SIZE
                + KDF_SALT_SIZE
                + KDF_LIMIT_SIZE
                + KDF_LIMIT_SIZE
                + KEYNUM_SK_SIZE
        {
            return Err(SError::new(
                crate::ErrorKind::SecretKey,
                "invalid secret key length",
            ));
        }
        let sig_alg = &sk_format[..ALG_SIZE];
        let kdf_alg = &sk_format[ALG_SIZE..ALG_SIZE + ALG_SIZE];
        let cksum_alg = &sk_format[ALG_SIZE + ALG_SIZE..ALG_SIZE + ALG_SIZE + ALG_SIZE];
        let kdf_salt = &sk_format
            [ALG_SIZE + ALG_SIZE + ALG_SIZE..ALG_SIZE + ALG_SIZE + ALG_SIZE + KDF_SALT_SIZE];
        let kdf_opslimit = u64::from_le_bytes(
            sk_format[ALG_SIZE + ALG_SIZE + ALG_SIZE + KDF_SALT_SIZE
                ..ALG_SIZE + ALG_SIZE + ALG_SIZE + KDF_SALT_SIZE + KDF_LIMIT_SIZE]
                .try_into()
                .unwrap(),
        );
        let kdf_memlimit = u64::from_le_bytes(
            sk_format[ALG_SIZE + ALG_SIZE + ALG_SIZE + KDF_SALT_SIZE + KDF_LIMIT_SIZE
                ..ALG_SIZE + ALG_SIZE + ALG_SIZE + KDF_SALT_SIZE + KDF_LIMIT_SIZE + KDF_LIMIT_SIZE]
                .try_into()
                .unwrap(),
        );

        let secret_key = SecretKey {
            sig_alg: sig_alg.try_into().unwrap(),
            kdf_alg: kdf_alg.try_into().unwrap(),
            cksum_alg: cksum_alg.try_into().unwrap(),
            kdf_salt: kdf_salt.try_into().unwrap(),
            kdf_opslimit,
            kdf_memlimit,
            keynum_sk: sk_format[ALG_SIZE
                + ALG_SIZE
                + ALG_SIZE
                + KDF_SALT_SIZE
                + KDF_LIMIT_SIZE
                + KDF_LIMIT_SIZE..]
                .try_into()
                .unwrap(),
        };
        Ok(SecretKeyBox::new(untrusted_comment, secret_key))
    } else {
        Err(SError::new(
            crate::ErrorKind::SecretKey,
            "missing untrusted comment",
        ))
    }
}

#[cfg(test)]
#[test]
fn test_parse_secret_key() {
    use crate::KeyPairBox;
    let password = b"password";
    let k = KeyPairBox::generate(Some(password), None, None).unwrap();
    let file = k.secret_key_box.to_string();
    let sk = parse_secret_key(&file).unwrap();
    assert_eq!(file, sk.to_string());
}
/// A `SecretKey` is used to sign messages.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub(crate) struct SecretKey {
    pub sig_alg: [u8; ALG_SIZE],
    kdf_alg: [u8; ALG_SIZE],
    cksum_alg: [u8; ALG_SIZE],
    kdf_salt: [u8; KDF_SALT_SIZE],
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    keynum_sk: [u8; KEYNUM_SK_SIZE],
}
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct KeynumSK {
    pub(crate) key_id: [u8; KID_SIZE],
    sec_key: RawSk,
    pub pub_key: ComponentBytes,
    checksum: [u8; CHK_SIZE],
}
impl KeynumSK {
    fn to_bytes(&self, mut kdf_buf: [u8; KEYNUM_SK_SIZE]) -> [u8; KEYNUM_SK_SIZE] {
        for (i, item) in kdf_buf.iter_mut().enumerate().take(KID_SIZE) {
            *item ^= self.key_id[i];
        }
        for i in 0..COMPONENT_SIZE {
            kdf_buf[KID_SIZE + i] ^= self.sec_key.0[i];
        }
        for i in 0..COMPONENT_SIZE {
            kdf_buf[KID_SIZE + COMPONENT_SIZE + i] ^= self.pub_key[i];
        }
        for i in 0..CHK_SIZE {
            kdf_buf[KID_SIZE + 2 * COMPONENT_SIZE + i] ^= self.checksum[i];
        }
        kdf_buf
    }
    fn from_bytes(keynum_sk: &[u8; KEYNUM_SK_SIZE], mut kdf_buf: [u8; KEYNUM_SK_SIZE]) -> Self {
        // let mut kdf_buf = [0u8; KEYNUM_SK_SIZE];
        for i in 0..KEYNUM_SK_SIZE {
            kdf_buf[i] ^= keynum_sk[i];
        }
        Self {
            key_id: kdf_buf[0..KID_SIZE].try_into().unwrap(),
            sec_key: RawSk(
                kdf_buf[KID_SIZE..KID_SIZE + COMPONENT_SIZE]
                    .try_into()
                    .unwrap(),
            ),
            pub_key: kdf_buf[KID_SIZE + COMPONENT_SIZE..KID_SIZE + 2 * COMPONENT_SIZE]
                .try_into()
                .unwrap(),
            checksum: kdf_buf[KID_SIZE + 2 * COMPONENT_SIZE..KEYNUM_SK_SIZE]
                .try_into()
                .unwrap(),
        }
    }
}
#[derive(Debug, Clone, ZeroizeOnDrop, Zeroize)]
struct RawSk(ComponentBytes);
impl Signer<ed25519::Signature> for RawSk {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<ed25519::Signature, ed25519::Error> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&self.0);
        Ok(sk.sign(msg))
    }
}
fn kdf(
    password: Option<&[u8]>,
    salt: &[u8; KDF_SALT_SIZE],
    opslimit: u64,
    memlimit: u64,
) -> Result<[u8; KEYNUM_SK_SIZE]> {
    let params = raw_scrypt_params(memlimit as usize, opslimit, N_LOG2_MAX)?;
    let mut stream = [0u8; KEYNUM_SK_SIZE];
    scrypt::scrypt(password.unwrap_or(&[]), salt, &params, &mut stream)?;
    Ok(stream)
}
impl SecretKey {
    pub fn sign(&self, message: &[u8], password: Option<&[u8]>) -> Result<ed25519::Signature> {
        let keynum_sk = self.xor_keynum_sk(password);
        Ok(keynum_sk?.sec_key.sign(message))
    }
    pub(crate) fn xor_keynum_sk(&self, password: Option<&[u8]>) -> Result<KeynumSK> {
        let stream = kdf(
            password,
            &self.kdf_salt,
            self.kdf_opslimit,
            self.kdf_memlimit,
        )?;

        let keynum_sk = KeynumSK::from_bytes(&self.keynum_sk, stream);

        let mut hash = Blake2b256::new();
        hash.update(self.sig_alg);
        hash.update(&keynum_sk.key_id);
        hash.update(&keynum_sk.sec_key.0);
        hash.update(&keynum_sk.pub_key);
        if hash.finalize().to_vec() != keynum_sk.checksum {
            return Err(SError::new(
                crate::ErrorKind::SecretKey,
                "checksum mismatch, invalid password",
            ));
        }
        Ok(keynum_sk)
    }
}
#[cfg(test)]
#[test]
fn test_sign() {
    use crate::{pub_key_from_sec_key, KeyPairBox};
    let password = b"password";
    let k = KeyPairBox::generate(Some(password), None, None).unwrap();
    let s = k.secret_key_box.to_string();
    let sk = parse_secret_key(&s).unwrap();
    let msg = b"hello world";
    let sig = sk.sign(msg, Some(password)).unwrap();
    let pk = pub_key_from_sec_key(&sk, Some(password)).unwrap();
    let v = pk.public_key.key.verify(msg, &sig);
    assert_eq!(v.unwrap(), true);
}

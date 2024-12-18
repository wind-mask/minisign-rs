use scrypt::password_hash::rand_core::{self, RngCore};

use crate::{errors::Result, PublicKeyBox, SecretKeyBox};

/// A `KeyPairBox` represents a minisign key pair.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPairBox<'p, 's> {
    /// The public key box.
    pub public_key_box: PublicKeyBox<'p>,
    /// The secret key box.
    pub secret_key_box: SecretKeyBox<'s>,
}
impl std::fmt::Display for KeyPairBox<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n{}", self.public_key_box, self.secret_key_box)
    }
}
impl<'p, 's> KeyPairBox<'p, 's> {
    /// Generate a new key pair.
    ///
    /// # Arguments
    /// * `password` - The password to encrypt the secret key.
    /// * `pk_comment` - The comment for the public key.
    /// * `sk_comment` - The comment for the secret key.
    ///
    /// # Returns
    /// A new key pair.
    ///
    /// # Errors
    /// * `ErrorKind::Kdf` - rng error
    pub fn generate(
        password: Option<&[u8]>,
        pk_comment: Option<&'p str>,
        sk_comment: Option<&'s str>,
    ) -> Result<Self> {
        let (pk, sk) = generate_keypair(password, pk_comment, sk_comment)?;
        Ok(Self {
            public_key_box: pk,
            secret_key_box: sk,
        })
    }
}
fn generate_keypair<'a, 'b>(
    password: Option<&[u8]>,
    pk_comment: Option<&'a str>,
    sk_comment: Option<&'b str>,
) -> Result<(PublicKeyBox<'a>, SecretKeyBox<'b>)> {
    let mut rng = rand_core::OsRng;
    let kid: [u8; 8] = rng.next_u64().to_le_bytes();
    let sign_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verify_key = sign_key.verifying_key();
    let sk = SecretKeyBox::from_signing_key(sign_key, &kid, password, sk_comment)?;
    let pk = PublicKeyBox::from_verifying_key(verify_key, &kid, pk_comment)?;
    Ok((pk, sk))
}

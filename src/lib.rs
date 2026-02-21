//
#![doc = include_str!("../README.md")]
mod constants;
use blake2::Digest;
use std::io::Read;

use constants::*;
mod errors;
pub use errors::*;
pub use public_key::PublicKeyBox;
use public_key::{PublicKey, RawPk};
pub use secret_key::SecretKeyBox;
use signature::Signature;
mod keypair;
pub use keypair::KeyPairBox;
mod public_key;
mod secret_key;
mod signature;
pub use signature::SignatureBox;

use crate::public_key::verify_prehashed;
mod util;
fn prehash<R>(data_reader: &mut R) -> Result<Vec<u8>>
where
    R: Read,
{
    let mut hash = blake2::Blake2b512::new();
    let mut buf = [0; 2048];
    loop {
        let n = data_reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().to_vec())
}
/// Create a new public key from a string in the minisign format pub key file
pub fn pub_key_from_str(s: &str) -> Result<PublicKeyBox<'_>> {
    PublicKeyBox::from_str(s)
}
/// Create a new secret key from a string in the minisign format key file
pub fn sec_key_from_str(s: &str) -> Result<SecretKeyBox<'_>> {
    SecretKeyBox::from_str(s)
}
/// Create a new public key from a secret key
///
/// default comment is None
pub fn pub_key_from_sec_key<'s>(
    sec_key: &SecretKeyBox<'s>,
    password: Option<&[u8]>,
) -> Result<PublicKeyBox<'s>> {
    let keynum_sk = sec_key.xor_keynum_sk(password)?;
    let pk_box = PublicKeyBox::new(
        None,
        PublicKey::new(
            sec_key.sig_alg(),
            keynum_sk.key_id,
            RawPk(keynum_sk.pub_key),
        ),
    );
    Ok(pk_box)
}

/// minisign some data
/// # Arguments
/// * `pk` - The public key to verify the signature(optional)
/// * `sk` - The secret key to sign the data
/// * `password` - The password to decrypt the secret key
/// * `data_reader` - The data to sign
/// * `trusted_comment` - The trusted comment for the signature
/// * `untrusted_comment` - The untrusted comment for the signature
/// # Returns
/// A Result containing the signature
/// # Errors
/// * `ErrorKind::Io` - If there is an error reading the data
/// * `ErrorKind::SecretKey` - If there is an error decrypting the secret key,password is wrong
/// * `ErrorKind::PublicKey` - If the public key is invalid or not matching the secret key
pub fn sign<'a, R>(
    pk: Option<&PublicKeyBox>,
    sk: &SecretKeyBox,
    password: Option<&[u8]>,
    mut data_reader: R,
    trusted_comment: Option<&'a str>,
    untrusted_comment: Option<&'a str>,
) -> Result<SignatureBox<'a>>
where
    R: Read,
{
    let prehashed = prehash(&mut data_reader)?;
    let sig = sk.sign(&prehashed, password)?;
    let mut global_data = sig.to_bytes().to_vec();
    global_data.extend_from_slice(trusted_comment.unwrap_or("").as_bytes());
    let global_sig = sk.sign(&global_data, password)?;
    let keynum_sk = sk.xor_keynum_sk(password)?;
    let signature = Signature::new(SIGALG_PREHASHED, keynum_sk.key_id, sig, global_sig);
    let sig_box = SignatureBox::new(untrusted_comment, trusted_comment, signature);
    if let Some(pk) = pk {
        verify_prehashed(pk, &sig_box, &prehashed)?;
    }
    Ok(sig_box)
}
/// Verify a minisign signature
/// # Arguments
/// * `pk` - The public key to verify the signature
/// * `signature_box` - The signature to verify
/// * `data_reader` - The data to verify
/// # Returns
/// A Result containing a boolean, true if the signature is valid
/// # Errors
/// * `ErrorKind::Io` - If there is an error reading the data
/// * `ErrorKind::PublicKey` - If the public key is invalid or not matching the signature
/// * `ErrorKind::PrehashedMismatch` - If the signature is not prehashed
pub fn verify<R>(
    pk: &PublicKeyBox,
    signature_box: &SignatureBox,
    mut data_reader: R,
) -> Result<bool>
where
    R: Read,
{
    let prehashed = prehash(&mut data_reader)?;
    verify_prehashed(pk, signature_box, &prehashed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let KeyPairBox {
            public_key_box,
            secret_key_box,
        } = KeyPairBox::generate(
            Some(b"password"),
            Some("pk untrusted comment"),
            Some("sk untrusted comment"),
        )
        .unwrap();
        let msg = "test";
        let sig_box = sign(
            Some(&public_key_box),
            &secret_key_box,
            Some(b"password"),
            msg.as_bytes(),
            Some("trusted comment"),
            Some("untrusted comment"),
        )
        .unwrap();
        let v = verify(&public_key_box, &sig_box, msg.as_bytes()).unwrap();
        assert_eq!(v, true);
    }
}

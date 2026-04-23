use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use mini_sign::{pub_key_from_str, sec_key_from_str, sign, verify, KeyPairBox, SignatureBox};

static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mini-sign-minisign-compat-{}-{counter}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("failed to create temporary test directory");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn path_arg(path: &Path) -> String {
    path.to_str()
        .expect("temporary path must be valid utf-8")
        .to_owned()
}

fn minisign_is_available() -> bool {
    Command::new("minisign")
        .arg("-v")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn skip_without_minisign() -> bool {
    if minisign_is_available() {
        true
    } else {
        eprintln!("skipping minisign compatibility test: minisign CLI not found");
        false
    }
}

fn run_minisign(args: &[String]) -> Output {
    let output = Command::new("minisign")
        .args(args)
        .output()
        .expect("failed to execute minisign");
    assert!(
        output.status.success(),
        "minisign {:?} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn library_signature_is_verified_by_official_minisign() {
    if !skip_without_minisign() {
        return;
    }

    let dir = TestDir::new();
    let message_path = dir.join("message.bin");
    let public_key_path = dir.join("minisign.pub");
    let signature_path = dir.join("message.minisig");
    let message = b"payload verified by the official minisign implementation\n\x00\x01\xff";

    let keypair = KeyPairBox::generate(
        Some(b"library password"),
        Some("library public key"),
        Some("library secret key"),
    )
    .expect("library key generation should succeed");
    let signature = sign(
        Some(&keypair.public_key_box),
        &keypair.secret_key_box,
        Some(b"library password"),
        &message[..],
        Some("library trusted comment"),
        Some("library untrusted comment"),
    )
    .expect("library signing should succeed");

    fs::write(&message_path, message).expect("failed to write message");
    fs::write(&public_key_path, keypair.public_key_box.to_string())
        .expect("failed to write public key");
    fs::write(&signature_path, signature.to_string()).expect("failed to write signature");

    run_minisign(&[
        "-V".to_owned(),
        "-q".to_owned(),
        "-m".to_owned(),
        path_arg(&message_path),
        "-p".to_owned(),
        path_arg(&public_key_path),
        "-x".to_owned(),
        path_arg(&signature_path),
    ]);
}

#[test]
fn official_minisign_artifacts_are_verified_by_library() {
    if !skip_without_minisign() {
        return;
    }

    let dir = TestDir::new();
    let message_path = dir.join("message.txt");
    let public_key_path = dir.join("official.pub");
    let secret_key_path = dir.join("official.key");
    let signature_path = dir.join("official.minisig");
    let message = b"payload signed by the official minisign implementation\n";

    fs::write(&message_path, message).expect("failed to write message");

    run_minisign(&[
        "-G".to_owned(),
        "-f".to_owned(),
        "-W".to_owned(),
        "-p".to_owned(),
        path_arg(&public_key_path),
        "-s".to_owned(),
        path_arg(&secret_key_path),
    ]);
    run_minisign(&[
        "-S".to_owned(),
        "-W".to_owned(),
        "-m".to_owned(),
        path_arg(&message_path),
        "-s".to_owned(),
        path_arg(&secret_key_path),
        "-x".to_owned(),
        path_arg(&signature_path),
        "-t".to_owned(),
        "official trusted comment".to_owned(),
        "-c".to_owned(),
        "official untrusted comment".to_owned(),
    ]);

    let public_key_text = fs::read_to_string(&public_key_path).expect("failed to read public key");
    let signature_text = fs::read_to_string(&signature_path).expect("failed to read signature");
    let public_key =
        pub_key_from_str(&public_key_text).expect("library should parse official public key");
    let signature =
        SignatureBox::from_str(&signature_text).expect("library should parse official signature");

    assert!(verify(&public_key, &signature, &message[..])
        .expect("library should verify official signature"));
}

#[test]
fn library_can_sign_with_official_secret_key_for_official_minisign() {
    if !skip_without_minisign() {
        return;
    }

    let dir = TestDir::new();
    let message_path = dir.join("message.txt");
    let public_key_path = dir.join("official.pub");
    let secret_key_path = dir.join("official.key");
    let signature_path = dir.join("library-from-official-key.minisig");
    let message = b"payload signed by mini-sign using an official minisign secret key\n";

    fs::write(&message_path, message).expect("failed to write message");

    run_minisign(&[
        "-G".to_owned(),
        "-f".to_owned(),
        "-W".to_owned(),
        "-p".to_owned(),
        path_arg(&public_key_path),
        "-s".to_owned(),
        path_arg(&secret_key_path),
    ]);

    let public_key_text = fs::read_to_string(&public_key_path).expect("failed to read public key");
    let secret_key_text = fs::read_to_string(&secret_key_path).expect("failed to read secret key");
    let public_key =
        pub_key_from_str(&public_key_text).expect("library should parse official public key");
    let secret_key =
        sec_key_from_str(&secret_key_text).expect("library should parse official secret key");
    let signature = sign(
        Some(&public_key),
        &secret_key,
        None,
        &message[..],
        Some("library trusted comment"),
        Some("library untrusted comment"),
    )
    .expect("library should sign with official secret key");

    fs::write(&signature_path, signature.to_string()).expect("failed to write signature");

    run_minisign(&[
        "-V".to_owned(),
        "-q".to_owned(),
        "-m".to_owned(),
        path_arg(&message_path),
        "-p".to_owned(),
        path_arg(&public_key_path),
        "-x".to_owned(),
        path_arg(&signature_path),
    ]);
}

#[test]
fn official_minisign_can_sign_with_library_unencrypted_secret_key() {
    if !skip_without_minisign() {
        return;
    }

    let dir = TestDir::new();
    let message_path = dir.join("message.txt");
    let public_key_path = dir.join("library.pub");
    let secret_key_path = dir.join("library.key");
    let signature_path = dir.join("official-from-library-key.minisig");
    let message = b"payload signed by official minisign using a mini-sign secret key\n";

    let keypair = KeyPairBox::generate(
        None,
        Some("library unencrypted public key"),
        Some("library unencrypted secret key"),
    )
    .expect("library key generation should succeed");

    fs::write(&message_path, message).expect("failed to write message");
    fs::write(&public_key_path, keypair.public_key_box.to_string())
        .expect("failed to write public key");
    fs::write(&secret_key_path, keypair.secret_key_box.to_string())
        .expect("failed to write secret key");

    run_minisign(&[
        "-S".to_owned(),
        "-W".to_owned(),
        "-m".to_owned(),
        path_arg(&message_path),
        "-s".to_owned(),
        path_arg(&secret_key_path),
        "-x".to_owned(),
        path_arg(&signature_path),
        "-t".to_owned(),
        "official trusted comment".to_owned(),
        "-c".to_owned(),
        "official untrusted comment".to_owned(),
    ]);
    run_minisign(&[
        "-V".to_owned(),
        "-q".to_owned(),
        "-m".to_owned(),
        path_arg(&message_path),
        "-p".to_owned(),
        path_arg(&public_key_path),
        "-x".to_owned(),
        path_arg(&signature_path),
    ]);

    let signature_text = fs::read_to_string(&signature_path).expect("failed to read signature");
    let signature =
        SignatureBox::from_str(&signature_text).expect("library should parse official signature");
    assert!(verify(&keypair.public_key_box, &signature, &message[..])
        .expect("library should verify official signature"));
}

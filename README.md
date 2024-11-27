

# minisign-rs

A Rust implementation lib of the [Minisign](https://jedisct1.github.io/minisign/).

Low-level library for the minisign system, designed to be used in CI/CD pipelines, or embedded into other processes (rather than manual command line).

## !!! This library not support legacy signature format !!!
## Example

``` rust
let KeyPairBox {
    public_key_box,
    secret_key_box,
} = KeyPairBox::generate(
    Some(b"password"),
    Some("pk untrusted comment"),
    Some("sk untrusted comment"),
)
.unwrap();
let mut pk_file = fs::File::create("./test.pub").unwrap();
let mut sk_file = fs::File::create("./test.sec").unwrap();
pk_file
    .write_all(public_key_box.to_string().as_bytes())
    .unwrap();
sk_file
    .write_all(secret_key_box.to_string().as_bytes())
    .unwrap();
let file = fs::File::open("./test").unwrap();
let sig_box = sign(
    Some(&public_key_box),
    &secret_key_box,
    Some(b"password"),
    file,
    Some("trusted comment"),
    Some("untrusted comment"),
)
.unwrap();
let mut sig_file = fs::File::create("./test.minisig").unwrap();
sig_file.write_all(sig_box.to_string().as_bytes()).unwrap();
let v = verify(&public_key_box, &sig_box, fs::File::open("./test").unwrap()).unwrap();
assert_eq!(v, true);
```
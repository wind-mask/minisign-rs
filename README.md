

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
```
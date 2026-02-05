# e2eel

![Pipeline Badge](https://gitlab.com/afesguerra/e2eel/badges/main/pipeline.svg?ignore_skipped=true)

> A Rust library for end-to-end encryption key management.

e2eel facilitates creating end-to-end encrypted services like Ente and Filen by simplifying secure, hierarchical key wrapping systems. It handles key derivation trees, root validation, and encrypted key storage complexity.

## Target Features

- Efficient DAG-based key hierarchy management
- Production-safe mutation APIs with robust error handling
- Seamless persistence integration
- Crypto-primitive agnostic design

## Development Status

This is a personal project for me to learn Rust, as well as give something back to open source community. While there is no plan to make it production ready for now, the goal is to learn enough of Rust to get there.

## Examples

### Set up new graph

```rust
use e2eel::{KeyChain, json::JsonStorage};

fn main() {
    let storage = JsonStorage::new(JSON_PATH.to_string());
    let mut keychain = KeyChain::<JsonStorage>::new(
        storage, // KeyStorage implementation for loading/persisting changes
        "kek", // ID of root key, e.g. kek or recovery
        b"test_password", // Password for PBKDF2
        b"test_salt", // Salt for PBKDF2
    )?;

    keychain.add_root(KEK_LABEL)?;
    keychain.add_wrapping(KEK_LABEL, MASTER_LABEL)?;
    keychain.add_wrapping(MASTER_LABEL, RECOVERY_LABEL)?;
    
    keychain.persist();
}
```

### Get subkey

```rust
use e2eel::{KeyChain, json::JsonStorage};

fn use_key(keychain: &KeyChain<JsonStorage>) {
    /*
     * Given that keychain was created with "kek" ID, this function will find the path to RECOVERY_LABEL key, traverse to it by decrypting the corresponding wrapping keys and returning the decrypted key.
     */
    let subkey = keychain.get_key(RECOVERY_LABEL)?;
}
```

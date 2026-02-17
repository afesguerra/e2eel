# e2eel

![Pipeline Badge](https://gitlab.com/afesguerra/e2eel/badges/main/pipeline.svg?ignore_skipped=true)

> A Rust library for end-to-end encryption key management.

e2eel facilitates creating end-to-end encrypted services like Ente and Filen by simplifying secure, hierarchical key wrapping systems. It handles key derivation trees, root validation, and encrypted key storage complexity.

## Target Features

- Efficient DAG-based key hierarchy management
- Production-safe mutation APIs with robust error handling
- Seamless persistence integration
- Crypto-primitive agnostic design
- Multiple encryption algorithms: AES-256-GCM and XSalsa20-Poly1305

## Crypto Providers

e2eel supports multiple encryption algorithms:

### AES-256-GCM (default)
- **Feature**: `aes256-gcm`
- **Key size**: 256 bits (32 bytes)
- **Authenticated encryption**: AES-GCM
- **Performance**: Hardware accelerated on most modern CPUs

### XSalsa20-Poly1305
- **Feature**: `xsalsa20-poly1305`
- **Key size**: 256 bits (32 bytes)  
- **Authenticated encryption**: XSalsa20 stream cipher + Poly1305 MAC
- **Performance**: Fast software implementation, good for embedded/mobile

## Development Status

This is a personal project for me to learn Rust, as well as give something back to open source community. While there is no plan to make it production ready for now, the goal is to learn enough of Rust to get there.

## Examples

### Set up new graph with AES-256-GCM

```rust
use e2eel::{KeyChain, keychain::aes256::Aes256GcmProvider, json::JsonStorage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = JsonStorage::new("keychain.json".to_string());
    let crypto = Aes256GcmProvider {};
    let kek_key = [0u8; 32]; // In practice, derive from password/PBKDF2
    
    let mut keychain = KeyChain::new(storage, crypto, "kek", &kek_key)?;

    keychain.add_root("kek")?;
    keychain.add_wrapping("kek", "master")?;
    keychain.add_wrapping("master", "recovery")?;
    
    keychain.persist()?;
    Ok(())
}
```

### Set up new graph with XSalsa20-Poly1305

```rust
use e2eel::{KeyChain, keychain::xsalsa20_poly1305::XSalsa20Poly1305Provider, json::JsonStorage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = JsonStorage::new("keychain.json".to_string());
    let crypto = XSalsa20Poly1305Provider {};
    let kek_key = [0u8; 32]; // In practice, derive from password/PBKDF2
    
    let mut keychain = KeyChain::new(storage, crypto, "kek", &kek_key)?;

    keychain.add_root("kek")?;
    keychain.add_wrapping("kek", "master")?;
    keychain.add_wrapping("master", "recovery")?;
    
    keychain.persist()?;
    Ok(())
}
```

### Get subkey

```rust
use e2eel::{KeyChain, keychain::aes256::Aes256GcmProvider, json::JsonStorage};

fn use_key(keychain: &KeyChain<JsonStorage, Aes256GcmProvider>) -> Result<(), Box<dyn std::error::Error>> {
    /*
     * Given that keychain was created with "kek" ID, this function will find 
     * the path to "recovery" key, traverse to it by decrypting the corresponding 
     * wrapping keys and returning the decrypted key.
     */
    let subkey = keychain.get_key("recovery")?;
    Ok(())
}
```

## Cargo Features

Enable the desired crypto provider(s) in your `Cargo.toml`:

```toml
[dependencies]
e2eel = { version = "0.1", features = ["aes256-gcm"] }
# or
e2eel = { version = "0.1", features = ["xsalsa20-poly1305"] }
# or both
e2eel = { version = "0.1", features = ["aes256-gcm", "xsalsa20-poly1305"] }
```

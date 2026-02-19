# e2eel

![Pipeline Badge](https://gitlab.com/afesguerra/e2eel/badges/main/pipeline.svg?ignore_skipped=true)

> A Rust library for end-to-end encryption key management.

e2eel is a key management library designed to power end-to-end encrypted services. It models encryption keys as nodes in a graph, where edges represent key wrappings (i.e., one key encrypted by another). To access a target key, the library traverses the graph from a known starting key, transitively decrypting each wrapping key along the path.

## How It Works

Keys and their relationships are stored as a directed graph (which may be cyclic). Each node in the graph represents an encryption key, and each edge represents a wrapping: the target key encrypted by the source key.

A key can have **multiple wrappings** from different parent keys. This enables multiple access paths to the same key — for example:

- A file's encryption key may be wrapped with the user's own master key (for self-access).
- The same file key may also be wrapped separately with another user's key (to share access with them).

When you request a key, e2eel finds the shortest path from your starting key to the target, then traverses and decrypts each wrapping along that path.

```
kek (root, derived from password)
 └──▶ master
       ├──▶ recovery
       └──▶ file_key ◀── shared_with_user_b (via user B's key wrapping)
```

## Features

- **Graph-based key hierarchy** — keys and wrappings form a graph (potentially cyclic) with multiple paths between nodes
- **Transitive key decryption** — automatically resolves and decrypts intermediate keys to reach a target
- **Multiple key wrappings** — a single key can be wrapped by several different parent keys, enabling shared access and recovery scenarios
- **Crypto-primitive agnostic** — bring your own crypto provider; multiple algorithms supported out of the box
- **Persistence integration** — built-in JSON storage with a trait-based interface for custom backends

## Supported Encryption Algorithms

### AES-256-GCM
- **Feature flag**: `aes256-gcm` *(enabled by default)*
- **Key size**: 256 bits (32 bytes)
- **Performance**: Hardware accelerated on most modern CPUs

### XSalsa20-Poly1305
- **Feature flag**: `xsalsa20-poly1305`
- **Key size**: 256 bits (32 bytes)
- **Performance**: Fast software implementation, well-suited for embedded/mobile

## Out of Scope

### Password-Based Key Derivation (PBKDF)

e2eel does **not** handle key derivation from passwords or other low-entropy secrets (e.g., Argon2id, PBKDF2, scrypt). The library expects to receive a fully derived encryption key as the entry point for graph traversal. Integrating a PBKDF to produce that initial key is the responsibility of the consuming application. This may change in the future.

### Encrypting Application Data

e2eel only handles the encryption and decryption of **keys**. It does not provide primitives for encrypting your application's actual content or files. The intended usage is:

1. Use e2eel to retrieve a decrypted content encryption key.
2. Use your own implementation (or a general-purpose crypto library) to encrypt/decrypt the actual data with that key.

## Examples

### Set up a new key graph with AES-256-GCM

```rust
use e2eel::{KeyChain, keychain::aes256::Aes256GcmProvider, json::JsonStorage, KeyStorage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = Aes256GcmProvider;
    let kek_key = [0u8; 32]; // Derive this from a password using Argon2id or similar

    let mut keychain = KeyChain::new(crypto, "kek", &kek_key)?;

    keychain.add_root("kek")?;
    keychain.add_wrapping("kek", "master")?;
    keychain.add_wrapping("master", "recovery")?;

    let mut storage = JsonStorage::new("keychain.json".to_string());
    storage.save(keychain.get_graph())?;
    Ok(())
}
```

### Set up a new key graph with XSalsa20-Poly1305

```rust
use e2eel::{KeyChain, keychain::xsalsa20_poly1305::XSalsa20Poly1305Provider, json::JsonStorage, KeyStorage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = XSalsa20Poly1305Provider;
    let kek_key = [0u8; 32]; // Derive this from a password using Argon2id or similar

    let mut keychain = KeyChain::new(crypto, "kek", &kek_key)?;

    keychain.add_root("kek")?;
    keychain.add_wrapping("kek", "master")?;
    keychain.add_wrapping("master", "recovery")?;

    let mut storage = JsonStorage::new("keychain.json".to_string());
    storage.save(keychain.get_graph())?;
    Ok(())
}
```

### Retrieve a key by traversing the graph

```rust
use e2eel::{KeyChain, keychain::aes256::Aes256GcmProvider};

fn use_key(keychain: &KeyChain<Aes256GcmProvider>) -> Result<(), Box<dyn std::error::Error>> {
    // Starting from "kek", e2eel finds the shortest path to "recovery",
    // transitively decrypting each wrapping key along the way.
    let subkey = keychain.get_key("recovery")?;
    Ok(())
}
```

### Share access to a key with another user

```rust
use e2eel::{KeyChain, keychain::aes256::Aes256GcmProvider, json::JsonStorage, KeyStorage};

fn share_file_key(
    keychain: &mut KeyChain<Aes256GcmProvider>,
    other_user_key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // "file_key" is already accessible via the owner's own key hierarchy.
    // Adding a second wrapping from another user's key creates an additional
    // path, granting that user access to "file_key" through their own root.
    keychain.add_wrapping(other_user_key_id, "file_key")?;

    let mut storage = JsonStorage::new("keychain.json".to_string());
    storage.save(keychain.get_graph())?;
    Ok(())
}
```

## Cargo Features

The following features are enabled by default:

| Feature | Description |
|---|---|
| `json` | JSON-based key graph persistence via `JsonStorage` |
| `aes256-gcm` | AES-256-GCM crypto provider |

To opt out of defaults and select features explicitly:

```toml
[dependencies]
# Default features (json + aes256-gcm) — no configuration needed
e2eel = { version = "0.1" }

# Only AES-256-GCM, without JSON storage
e2eel = { version = "0.1", default-features = false, features = ["aes256-gcm"] }

# XSalsa20-Poly1305 in addition to the defaults
e2eel = { version = "0.1", features = ["xsalsa20-poly1305"] }

# All supported algorithms
e2eel = { version = "0.1", features = ["aes256-gcm", "xsalsa20-poly1305"] }
```

## Development Status

This is a personal project for learning Rust while contributing to the open-source community. The goal is to grow it into a production-ready library over time. Feedback and contributions are welcome.

See [ROADMAP.md](./ROADMAP.md) for planned features.


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
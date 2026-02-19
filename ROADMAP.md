# e2eel Roadmap

This document tracks planned features and improvements for e2eel. Items are loosely ordered by priority, but may be implemented in any order.

## Planned Features

### Asymmetric Key Wrapping

> Enable sharing access to keys using asymmetric cryptography.

Currently, all key wrappings rely on symmetric encryption. Supporting asymmetric key wrapping (e.g., using RSA-OAEP or X25519+AEAD hybrid encryption) would allow one user to grant another user access to a key using only the recipient's public key — without requiring a shared secret.

This is a prerequisite for proper multi-user sharing flows:
- User A wraps a file key with User B's public key.
- User B can decrypt the wrapping using their own private key, without User A ever knowing User B's private key.

### XChaCha20-Poly1305 Support

> Add XChaCha20-Poly1305 as an additional symmetric encryption algorithm.

XChaCha20-Poly1305 offers a larger nonce space (192-bit) compared to the standard ChaCha20-Poly1305 (96-bit), making random nonce generation safer for high-volume use cases. It is well-supported in the Rust ecosystem via the `chacha20poly1305` crate and complements the existing AES-256-GCM and XSalsa20-Poly1305 providers.

### Zeroize Integration for Secret Memory Safety

> Ensure key material is reliably erased from memory after use.

`zeroize` is already listed as a dependency but is not yet actively applied to key types or intermediate values within the library. Without explicit zeroing, sensitive key bytes may linger in memory after they are no longer needed, making them potentially recoverable through memory dumps or similar attacks.

This work would involve:
- Implementing `Zeroize` and `ZeroizeOnDrop` on key types returned by `CryptoProvider`.
- Ensuring intermediate decrypted keys produced during graph traversal are zeroed once the final key is reached.
- Auditing all code paths where key material is held to eliminate unintentional copies that escape zeroing.

### Recovery Key Generation Helpers

> Provide convenience APIs for generating and registering recovery keys.

Recovery keys are already achievable manually by adding an extra wrapping from a recovery key node. However, generating a cryptographically secure recovery key, encoding it in a human-friendly format (e.g., Base58 word list), and wiring it into the graph involves boilerplate that most integrators will repeat.

This feature would provide:
- A helper to generate a recovery key and automatically add it as a wrapping to a target node.
- Optional encoding/decoding utilities for presenting recovery keys to users.

---

## Out of Scope (For Now)

The following are explicitly **not** planned for the near term but may be revisited:

- **PBKDF integration** (Argon2id, PBKDF2, scrypt): key derivation from passwords remains the responsibility of the consuming application.
- **Content encryption**: e2eel will continue to focus exclusively on key management, not on encrypting application data.
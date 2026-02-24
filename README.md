# e2eel

[![Build](https://github.com/afesguerra/e2eel/actions/workflows/rust.yml/badge.svg)](https://github.com/afesguerra/e2eel/actions/workflows/rust.yml)

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

## Examples

See [EXAMPLES.md](./EXAMPLES.md) for comprehensive usage examples.

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

### Learning in Progress

I am **not a security expert**. This project is a learning vehicle for me to understand cryptography, Rust, and secure coding practices more deeply. I am learning about key management, encryption algorithms, and their proper use as I build this library. While I take security seriously and review all code carefully, some design decisions or implementation details may be imperfect or suboptimal as my knowledge evolves.

If you are a security researcher or cryptography expert, feedback and critique are especially welcome. This project benefits from the collective knowledge of the community.

### Iteration Without Community Review

Currently, this is a solo project without an active community or PR review process. This means I iterate directly on the codebase, refactoring and improving as I learn and discover better approaches. There is no formal code review gate, which allows for rapid experimentation but also means the responsibility for correctness rests entirely with me.

As the project matures and gains community contributors, I plan to introduce a formal review process. Until then, I iterate continuously, fixing issues and improving the design based on my own testing and learning.

## On AI-Assisted Development

I have been a sort of "AI luddite" for a while but in order to not fight back against new tools just because they are unfamiliar, I am using AI assistance as a development tool and learning resource. However, **I review and understand every single change** before it is committed (both as I would with any PR but also for learning Rust). I am opposed to "vibe-coding" — the practice of accepting AI-generated code without meaningful review or understanding.

My approach:
- ✅ Use AI to explore ideas, generate boilerplate, and accelerate development
- ✅ Review all AI suggestions critically before acceptance
- ✅ Understand the implications of every change, especially for security-sensitive code
- ✅ Treat AI assistance as a learning opportunity to deepen my understanding of Rust and cryptography
- ❌ Never blindly accept generated code
- ❌ Never skip security considerations or defer to AI judgment on correctness

Given that this library deals with encryption key management, security is non-negotiable. All code must be thoroughly reviewed and understood, regardless of its source.

(and yes, this documentation was generated with AI and I did read it all and tweaked it)
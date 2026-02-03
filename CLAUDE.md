# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CoReVo (Commit-Reveal-Voting) is a Rust CLI tool for implementing confidential group voting on Substrate-based blockchains using only `System.Remark` extrinsics. It enables secret ballot voting where votes remain private until revealed, preventing vote influence within groups.

## Build Commands

```bash
cargo build              # Debug build
cargo build --release    # Release build
cargo run                # Run against Kusama Asset Hub (currently hardcoded)
cargo check              # Quick type checking
```

**Note:** Requires Rust nightly (edition 2024). Current toolchain: rustc 1.95.0-nightly.

## Architecture

### Module Structure

- **primitives.rs** - Core data structures: `VotingAccount`, `CorevoRemark` (versioned), `CorevoMessage` (4 message types for voting phases), `CorevoVote` (Aye/Nay/Abstain)
- **crypto.rs** - X25519 key derivation from seed phrases, ChaCha20-Poly1305 encryption/decryption
- **chain_helpers.rs** - Substrate chain interaction via subxt: block subscription, remark submission
- **indexer.rs** - MongoDB integration for vote history queries; handles decryption and vote revelation via brute-force hash matching
- **main.rs** - Application entry point with hardcoded test scenario

### Key Design Patterns

**Remark Prefix:** All on-chain remarks use `0xcc00ee` prefix for efficient filtering in litescan/MongoDB.

**Versioned Encoding:** `CorevoRemark` enum allows future protocol versions without breaking changes.

**Deterministic Keys:** X25519 encryption keys derived from same seed phrase as SR25519 signing keys via BLAKE2b - no separate key storage needed.

**Commitment Scheme:** `hash(vote || one_time_salt || common_salt)` binds votes cryptographically. Vote revelation works by brute-forcing all 3 vote options against the commitment.

### Voting Protocol Phases

1. **Initialization** - Announce X25519 public key (once per voter)
2. **Invite** - Proposer sends encrypted common salt to each voter
3. **Commit** - Submit commitment hash + self-encrypted vote
4. **Reveal** - Publish one-time salt for verification

## Chain Metadata

Pre-cached metadata files exist for multiple chains. To update:

```bash
cargo install subxt-cli
subxt metadata --url wss://sys.ibp.network/asset-hub-kusama:443 > kusama_asset_hub_metadata.scale
```

## MongoDB / Litescan

Vote history is indexed via [litescan](https://github.com/pifragile/litescan) into MongoDB (`litescan_kusama_assethub` database).

Query all CoReVo remarks:
```
{method: "remark", "args.remark": { $regex: /^0xcc00ee/i }}
```

## Key Dependencies

- **subxt** (v0.44) - Substrate client
- **x25519-dalek**, **crypto_box** - Encryption
- **blake2** - Hashing for commitments
- **parity-scale-codec** - Substrate encoding
- **tokio** - Async runtime
- **mongodb** - Vote history indexing

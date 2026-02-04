use std::str::FromStr;

use blake2::{
    Blake2b, Blake2b512,
    digest::{Digest, consts::U64},
};
use crypto_box::{
    ChaChaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey,
    aead::{Aead, AeadCore, OsRng},
};
use subxt_signer::{ExposeSecret, SecretUri, sr25519::Keypair};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{CorevoError, Result};
use crate::primitives::VotingAccount;

/// SS58 address prefix for Substrate (generic)
pub const SS58_PREFIX_SUBSTRATE: u16 = 42;
/// SS58 address prefix for Kusama
pub const SS58_PREFIX_KUSAMA: u16 = 2;
/// SS58 address prefix for Polkadot
pub const SS58_PREFIX_POLKADOT: u16 = 0;

/// Derive a VotingAccount from a secret URI (e.g., "//Alice" or mnemonic phrase)
///
/// This derives both SR25519 signing keypair and X25519 encryption keypair
/// from the same seed, using BLAKE2b for the X25519 derivation.
pub fn derive_account_from_uri(secret_uri: &str) -> Result<VotingAccount> {
    let uri = SecretUri::from_str(secret_uri)?;
    let sr25519_keypair = Keypair::from_uri(&uri)?;

    // Derive X25519 keypair using BLAKE2b hash of seed phrase + derivation path
    let mut hasher = Blake2b512::new();
    hasher.update(uri.phrase.expose_secret().as_bytes());
    if let Some(password) = &uri.password {
        hasher.update(password.expose_secret().as_bytes());
    }
    // Include junctions in derivation
    for junction in &uri.junctions {
        hasher.update(format!("{:?}", junction).as_bytes());
    }
    let hash = hasher.finalize();

    let x25519_secret = StaticSecret::from(<[u8; 32]>::try_from(&hash[..32]).unwrap());
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    Ok(VotingAccount {
        sr25519_keypair,
        x25519_public,
        x25519_secret,
    })
}

/// Encrypt data for a recipient using X25519 + ChaCha20-Poly1305
///
/// Returns: nonce (24 bytes) || ciphertext
pub fn encrypt_for_recipient(
    sender_x25519_secret: &StaticSecret,
    recipient_x25519_public: &X25519PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let their_box_public = BoxPublicKey::from(*recipient_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(sender_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = crypto_box.encrypt(&nonce, plaintext)?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data from a sender using X25519 + ChaCha20-Poly1305
///
/// Expects: nonce (24 bytes) || ciphertext
pub fn decrypt_from_sender(
    recipient_x25519_secret: &StaticSecret,
    sender_x25519_public: &X25519PublicKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 {
        return Err(CorevoError::Decryption("Ciphertext too short".to_string()));
    }

    let (nonce_bytes, encrypted_data) = ciphertext.split_at(24);
    let nonce = crypto_box::Nonce::from_slice(nonce_bytes);

    let their_box_public = BoxPublicKey::from(*sender_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(recipient_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    let plaintext = crypto_box.decrypt(nonce, encrypted_data)?;
    Ok(plaintext)
}

/// Encode a 32-byte public key as an SS58 address with the given prefix
///
/// SS58 format: prefix (1-2 bytes) + account (32 bytes) + checksum (2 bytes)
/// All encoded with base58
pub fn encode_ss58(public_key: &[u8; 32], prefix: u16) -> String {
    const SS58_PREFIX: &[u8] = b"SS58PRE";

    let mut data = Vec::with_capacity(35);

    // Encode prefix (simple format for prefix < 64, full format otherwise)
    if prefix < 64 {
        data.push(prefix as u8);
    } else {
        // Two-byte prefix encoding
        data.push(((prefix & 0x00FC) >> 2) as u8 | 0x40);
        data.push(((prefix >> 8) as u8) | ((prefix & 0x0003) << 6) as u8);
    }

    // Add the public key
    data.extend_from_slice(public_key);

    // Calculate checksum using Blake2b-512
    let mut hasher = Blake2b::<U64>::new();
    hasher.update(SS58_PREFIX);
    hasher.update(&data);
    let hash = hasher.finalize();

    // Append first 2 bytes of hash as checksum
    data.push(hash[0]);
    data.push(hash[1]);

    // Base58 encode
    bs58::encode(data).into_string()
}

/// Derive just the SS58 address from a secret URI
///
/// Returns the address encoded with the specified SS58 prefix
pub fn derive_address_from_uri(secret_uri: &str, ss58_prefix: u16) -> Result<String> {
    let uri = SecretUri::from_str(secret_uri)?;
    let keypair = Keypair::from_uri(&uri)?;
    let public_key: [u8; 32] = keypair.public_key().0;
    Ok(encode_ss58(&public_key, ss58_prefix))
}

/// Format an AccountId32 as SS58 with the given prefix
pub fn format_account_ss58(account: &subxt::utils::AccountId32, ss58_prefix: u16) -> String {
    encode_ss58(&account.0, ss58_prefix)
}

/// Get the SS58 prefix for a chain URL
///
/// Returns the appropriate prefix based on the chain URL
pub fn ss58_prefix_for_chain(chain_url: &str) -> u16 {
    let url_lower = chain_url.to_lowercase();
    if url_lower.contains("kusama") || url_lower.contains("ksm") {
        SS58_PREFIX_KUSAMA
    } else if url_lower.contains("polkadot") || url_lower.contains("dot") {
        SS58_PREFIX_POLKADOT
    } else {
        SS58_PREFIX_SUBSTRATE
    }
}

/// Chain token metadata
pub struct ChainTokenInfo {
    pub symbol: &'static str,
    pub decimals: u8,
}

/// Get token info (symbol and decimals) for a chain URL
pub fn token_info_for_chain(chain_url: &str) -> ChainTokenInfo {
    let url_lower = chain_url.to_lowercase();
    if url_lower.contains("kusama") || url_lower.contains("ksm") {
        ChainTokenInfo {
            symbol: "KSM",
            decimals: 12,
        }
    } else if url_lower.contains("polkadot") || url_lower.contains("dot") {
        ChainTokenInfo {
            symbol: "DOT",
            decimals: 10,
        }
    } else if url_lower.contains("westend") || url_lower.contains("wnd") {
        ChainTokenInfo {
            symbol: "WND",
            decimals: 12,
        }
    } else if url_lower.contains("paseo") || url_lower.contains("pas") {
        ChainTokenInfo {
            symbol: "PAS",
            decimals: 10,
        }
    } else {
        ChainTokenInfo {
            symbol: "UNIT",
            decimals: 12,
        }
    }
}

/// Format a balance with the correct decimals
pub fn format_balance(balance: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let whole = balance / divisor;
    let frac = balance % divisor;

    if frac == 0 {
        format!("{}", whole)
    } else {
        // Format with up to 4 decimal places, trimming trailing zeros
        let frac_str = format!("{:0>width$}", frac, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        let display_frac = if trimmed.len() > 4 {
            &trimmed[..4]
        } else {
            trimmed
        };
        format!("{}.{}", whole, display_frac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known test vector: //Alice on Substrate
    // SR25519 pubkey: 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
    const ALICE_PUBKEY: [u8; 32] = [
        0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f,
        0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d,
        0xa2, 0x7d,
    ];

    #[test]
    fn test_derive_account_from_uri_alice() {
        let account = derive_account_from_uri("//Alice").unwrap();
        let pubkey: [u8; 32] = account.sr25519_keypair.public_key().0;
        assert_eq!(pubkey, ALICE_PUBKEY);
    }

    #[test]
    fn test_derive_account_from_uri_bob() {
        // Ensure different dev accounts produce different keys
        let alice = derive_account_from_uri("//Alice").unwrap();
        let bob = derive_account_from_uri("//Bob").unwrap();

        let alice_pubkey: [u8; 32] = alice.sr25519_keypair.public_key().0;
        let bob_pubkey: [u8; 32] = bob.sr25519_keypair.public_key().0;

        assert_ne!(alice_pubkey, bob_pubkey);
    }

    #[test]
    fn test_derive_account_x25519_keys_generated() {
        let account = derive_account_from_uri("//Alice").unwrap();

        // X25519 public key should be derivable from secret
        let derived_public = X25519PublicKey::from(&account.x25519_secret);
        assert_eq!(account.x25519_public, derived_public);
    }

    #[test]
    fn test_derive_account_invalid_uri() {
        // Completely invalid URI
        let result = derive_account_from_uri("not a valid uri !@#$%");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_ss58_substrate_prefix() {
        // //Alice with Substrate prefix (42)
        let address = encode_ss58(&ALICE_PUBKEY, SS58_PREFIX_SUBSTRATE);
        assert_eq!(address, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
    }

    #[test]
    fn test_encode_ss58_kusama_prefix() {
        // //Alice with Kusama prefix (2)
        let address = encode_ss58(&ALICE_PUBKEY, SS58_PREFIX_KUSAMA);
        assert_eq!(address, "HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F");
    }

    #[test]
    fn test_encode_ss58_polkadot_prefix() {
        // //Alice with Polkadot prefix (0)
        let address = encode_ss58(&ALICE_PUBKEY, SS58_PREFIX_POLKADOT);
        assert_eq!(address, "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5");
    }

    #[test]
    fn test_derive_address_from_uri_roundtrip() {
        let address = derive_address_from_uri("//Alice", SS58_PREFIX_SUBSTRATE).unwrap();
        assert_eq!(address, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
    }

    #[test]
    fn test_ss58_prefix_for_chain_kusama() {
        assert_eq!(
            ss58_prefix_for_chain("wss://kusama-rpc.polkadot.io"),
            SS58_PREFIX_KUSAMA
        );
        assert_eq!(
            ss58_prefix_for_chain("wss://asset-hub-kusama.api.onfinality.io"),
            SS58_PREFIX_KUSAMA
        );
        assert_eq!(
            ss58_prefix_for_chain("wss://ksm.api.example.com"),
            SS58_PREFIX_KUSAMA
        );
    }

    #[test]
    fn test_ss58_prefix_for_chain_polkadot() {
        assert_eq!(
            ss58_prefix_for_chain("wss://rpc.polkadot.io"),
            SS58_PREFIX_POLKADOT
        );
        assert_eq!(
            ss58_prefix_for_chain("wss://dot.api.example.com"),
            SS58_PREFIX_POLKADOT
        );
    }

    #[test]
    fn test_ss58_prefix_for_chain_default() {
        assert_eq!(
            ss58_prefix_for_chain("wss://some-unknown-chain.io"),
            SS58_PREFIX_SUBSTRATE
        );
        assert_eq!(
            ss58_prefix_for_chain("wss://localhost:9944"),
            SS58_PREFIX_SUBSTRATE
        );
    }

    #[test]
    fn test_token_info_for_chain_kusama() {
        let info = token_info_for_chain("wss://kusama-rpc.polkadot.io");
        assert_eq!(info.symbol, "KSM");
        assert_eq!(info.decimals, 12);
    }

    #[test]
    fn test_token_info_for_chain_polkadot() {
        let info = token_info_for_chain("wss://rpc.polkadot.io");
        assert_eq!(info.symbol, "DOT");
        assert_eq!(info.decimals, 10);
    }

    #[test]
    fn test_token_info_for_chain_westend() {
        // The URL must contain "westend" or "wnd" to match
        let info = token_info_for_chain("wss://wnd-rpc.example.com");
        assert_eq!(info.symbol, "WND");
        assert_eq!(info.decimals, 12);
    }

    #[test]
    fn test_token_info_for_chain_paseo() {
        let info = token_info_for_chain("wss://paseo.api.example.com");
        assert_eq!(info.symbol, "PAS");
        assert_eq!(info.decimals, 10);
    }

    #[test]
    fn test_token_info_for_chain_default() {
        let info = token_info_for_chain("wss://unknown-chain.io");
        assert_eq!(info.symbol, "UNIT");
        assert_eq!(info.decimals, 12);
    }

    #[test]
    fn test_format_balance_whole_number() {
        assert_eq!(format_balance(1_000_000_000_000, 12), "1");
        assert_eq!(format_balance(5_000_000_000_000, 12), "5");
        assert_eq!(format_balance(0, 12), "0");
    }

    #[test]
    fn test_format_balance_with_decimals() {
        // 1.5 KSM
        assert_eq!(format_balance(1_500_000_000_000, 12), "1.5");
        // 1.25 KSM
        assert_eq!(format_balance(1_250_000_000_000, 12), "1.25");
        // 1.125 KSM
        assert_eq!(format_balance(1_125_000_000_000, 12), "1.125");
    }

    #[test]
    fn test_format_balance_truncates_to_4_decimals() {
        // 1.123456789... should show as 1.1234
        assert_eq!(format_balance(1_123_456_789_000, 12), "1.1234");
    }

    #[test]
    fn test_format_balance_trims_trailing_zeros() {
        // 1.1000 should be 1.1
        assert_eq!(format_balance(1_100_000_000_000, 12), "1.1");
        // 1.1200 should be 1.12
        assert_eq!(format_balance(1_120_000_000_000, 12), "1.12");
    }

    #[test]
    fn test_format_balance_different_decimals() {
        // DOT has 10 decimals
        assert_eq!(format_balance(10_000_000_000, 10), "1");
        assert_eq!(format_balance(15_000_000_000, 10), "1.5");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice = derive_account_from_uri("//Alice").unwrap();
        let bob = derive_account_from_uri("//Bob").unwrap();

        let plaintext = b"secret message for bob";

        // Alice encrypts for Bob
        let ciphertext =
            encrypt_for_recipient(&alice.x25519_secret, &bob.x25519_public, plaintext).unwrap();

        // Bob decrypts from Alice
        let decrypted =
            decrypt_from_sender(&bob.x25519_secret, &alice.x25519_public, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_self() {
        let alice = derive_account_from_uri("//Alice").unwrap();
        let plaintext = b"note to self";

        // Alice encrypts for herself
        let ciphertext =
            encrypt_for_recipient(&alice.x25519_secret, &alice.x25519_public, plaintext).unwrap();

        // Alice decrypts
        let decrypted =
            decrypt_from_sender(&alice.x25519_secret, &alice.x25519_public, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_ciphertext_too_short() {
        let alice = derive_account_from_uri("//Alice").unwrap();

        // Ciphertext must be at least 24 bytes (nonce size)
        let short_ciphertext = vec![0u8; 10];
        let result = decrypt_from_sender(
            &alice.x25519_secret,
            &alice.x25519_public,
            &short_ciphertext,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let alice = derive_account_from_uri("//Alice").unwrap();
        let bob = derive_account_from_uri("//Bob").unwrap();
        let charlie = derive_account_from_uri("//Charlie").unwrap();

        let plaintext = b"secret for bob";

        // Alice encrypts for Bob
        let ciphertext =
            encrypt_for_recipient(&alice.x25519_secret, &bob.x25519_public, plaintext).unwrap();

        // Charlie tries to decrypt (should fail)
        let result = decrypt_from_sender(&charlie.x25519_secret, &alice.x25519_public, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_format_account_ss58() {
        use subxt::utils::AccountId32;

        let account_id = AccountId32(ALICE_PUBKEY);
        let address = format_account_ss58(&account_id, SS58_PREFIX_SUBSTRATE);
        assert_eq!(address, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
    }
}

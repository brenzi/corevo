use std::str::FromStr;

use blake2::{Blake2b512, Blake2b, digest::{consts::U64, Digest}};
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    ChaChaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey,
};
use subxt_signer::{sr25519::Keypair, ExposeSecret, SecretUri};
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
        ChainTokenInfo { symbol: "KSM", decimals: 12 }
    } else if url_lower.contains("polkadot") || url_lower.contains("dot") {
        ChainTokenInfo { symbol: "DOT", decimals: 10 }
    } else if url_lower.contains("westend") || url_lower.contains("wnd") {
        ChainTokenInfo { symbol: "WND", decimals: 12 }
    } else if url_lower.contains("paseo") || url_lower.contains("pas") {
        ChainTokenInfo { symbol: "PAS", decimals: 10 }
    } else {
        ChainTokenInfo { symbol: "UNIT", decimals: 12 }
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

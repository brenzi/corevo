use std::str::FromStr;
use subxt::{
    utils::{AccountId32, MultiAddress},
    OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::dev::{self};
use futures::StreamExt;
use subxt_signer::{ExposeSecret, SecretUri};
use subxt_signer::sr25519::Keypair;
use rand::{random};
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, ChaChaBox, aead::{Aead, AeadCore, OsRng}};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use sha2::{Sha512, Digest};

#[subxt::subxt(runtime_metadata_path = "paseo_people_metadata.scale")]
pub mod assethub {}

// PolkadotConfig or SubstrateConfig will suffice for this example at the moment,
// but PolkadotConfig is a little more correct, having the right `Address` type.
type AssetHubConfig = PolkadotConfig;

pub struct VotingAccount {
    pub sr25519_keypair: Keypair,
    pub x25519_public: X25519PublicKey,
    pub x25519_secret: StaticSecret,
}

#[tokio::main]
pub async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let api = OnlineClient::<AssetHubConfig>::from_url("wss://sys.ibp.network/people-paseo").await?;
    println!("Connection with parachain established.");

    let (proposer,
        voter_b) = tokio::try_join!(
        derive_account(&api, "//KvPoPperA"),
        derive_account(&api, "//KvPoPperB")
    )?;
    let common_salt = random::<[u8; 32]>();
    println!("common salt: {:?}", common_salt);
    let ciphertext = encrypt_for_recipient(&proposer.x25519_secret, &voter_b.x25519_public, &common_salt).unwrap();
    println!("Encrypted message from proposer to voter B: {:?}", ciphertext);
    let plaintext_at_voter_b = decrypt_from_sender(&voter_b.x25519_secret, &proposer.x25519_public, ciphertext.as_slice()).unwrap();
    println!("Decrypted message at voter B: {:?}", plaintext_at_voter_b);


    let api_for_blocks = api.clone();
    let listener_handle = tokio::spawn(async move {
        if let Err(e) = listen_to_blocks(api_for_blocks).await {
            eprintln!("block subscription task failed: {e}");
        }
    });
    println!("Listening to System.Remark Extrinsics in new finalized blocks...");

    listener_handle.await?;
    Ok(())
}


async fn derive_account(api: &OnlineClient<AssetHubConfig>, secret: &str) -> Result<VotingAccount, Box<dyn std::error::Error>> {
    let uri = SecretUri::from_str(secret)?;
    let sr25519_keypair = Keypair::from_uri(&uri)?;

    // derive X25519 keypair
    let mut hasher = Sha512::new();
    hasher.update(uri.phrase.expose_secret().as_bytes());
    if let Some(password) = &uri.password {
        hasher.update(password.expose_secret().as_bytes());
    }
    // Add junctions for derivation path
    for junction in &uri.junctions {
        hasher.update(format!("{:?}", junction).as_bytes());
    }
    let hash = hasher.finalize();

    let x25519_secret = StaticSecret::from(<[u8; 32]>::try_from(&hash[..32]).unwrap());
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // check account on chain
    let account_id = sr25519_keypair.public_key().to_account_id();
    println!("Address for {}: {}", secret, account_id);
    let storage = api.storage().at_latest().await?;
    let account_info = storage
        .fetch(&assethub::storage().system().account(account_id))
        .await?.expect("Account should exist");
    println!("   {} has balance of {:?}", secret, account_info.data.free);
    Ok(VotingAccount { sr25519_keypair, x25519_public, x25519_secret })
}

async fn listen_to_blocks(api: OnlineClient<AssetHubConfig>) -> Result<(), Box<dyn std::error::Error>> {
    let mut blocks = api.blocks().subscribe_finalized().await?;
    while let Some(block) = blocks.next().await {
        let block = block?;

        let block_number = block.number();
        let block_hash = block.hash();

        println!("Block #{block_number}:");
        println!("  Hash: {block_hash}");
        println!("  Extrinsics:");

        let extrinsics = block.extrinsics().await?;

        for ext in extrinsics.iter() {
            if let Some(remark) = ext.as_extrinsic::<assethub::system::calls::types::Remark>()? {
                println!("Remark: {:?}", remark);
            }
            if let Some(transfer) = ext.as_extrinsic::<assethub::balances::calls::types::TransferKeepAlive>()? {
                println!("Transfer: {:?}", transfer);
            }
        }
    }
    Ok(())
}

/// Encrypt 32 bytes for a recipient using their X25519 public key
pub fn encrypt_for_recipient(
    sender_x25519_secret: &StaticSecret,
    recipient_x25519_public: &X25519PublicKey,
    plaintext: &[u8; 32],
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let their_box_public = BoxPublicKey::from(*recipient_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(sender_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = crypto_box.encrypt(&nonce, plaintext.as_ref())?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt message from sender using their X25519 public key
pub fn decrypt_from_sender(
    recipient_x25519_secret: &StaticSecret,
    sender_x25519_public: &X25519PublicKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    // Extract nonce (first 24 bytes) and ciphertext (rest)
    if ciphertext.len() < 24 {
        return Err(crypto_box::aead::Error);
    }

    let (nonce_bytes, encrypted_data) = ciphertext.split_at(24);
    let nonce = crypto_box::Nonce::from_slice(nonce_bytes);

    // Create crypto_box from recipient secret and sender public
    let their_box_public = BoxPublicKey::from(*sender_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(recipient_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    // Decrypt
    let plaintext = crypto_box.decrypt(nonce, encrypted_data)?;
    Ok(plaintext)
}

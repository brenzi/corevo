mod primitives;
mod crypto;
mod chain_helpers;
mod indexer;

use primitives::{CorevoRemark, CorevoRemarkV1, CorevoMessage, CorevoVote, CorevoVoteAndSalt};
use crypto::{encrypt_for_recipient, decrypt_from_sender, derive_account};
use chain_helpers::{listen_to_blocks, send_remark};
use indexer::get_history;
use std::collections::HashMap;
use subxt::{
    OnlineClient, PolkadotConfig,
};
use rand::random;
use codec::Encode;
use futures::future::join_all;
use crate::primitives::{CorevoContext, Salt};

// [subxt::subxt(runtime_metadata_path = "paseo_people_metadata.scale")]
#[subxt::subxt(runtime_metadata_path = "kusama_asset_hub_metadata.scale")]
pub mod assethub {}

// PolkadotConfig or SubstrateConfig will suffice for this example at the moment,
// but PolkadotConfig is a little more correct, having the right `Address` type.
type AssetHubConfig = PolkadotConfig;

/// we prefix our remarks with a unique byte sequence to identify them easily.
const COREVO_REMARK_PREFIX: [u8; 3] = hex_literal::hex!("cc00ee");
const CONTEXT: &str = "corevo_test_voting_2";

#[tokio::main]
pub async fn main() {
    env_logger::init();
    if let Err(err) = run().await {
        eprintln!("{err}");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    //let api = OnlineClient::<AssetHubConfig>::from_url("wss://sys.ibp.network/people-paseo").await?;
    let api = OnlineClient::<AssetHubConfig>::from_url("wss://sys.ibp.network/asset-hub-kusama:443").await?;
    println!("Connection with parachain established.");

    let (proposer,
        voter_b) = tokio::try_join!(
        derive_account(&api, "//KvPoPperA"),
        derive_account(&api, "//KvPoPperB")
    )?;
    let everybody = vec![&proposer, &voter_b];

    let api_for_blocks = api.clone();
    let listener_handle = tokio::spawn(async move {
        if let Err(e) = listen_to_blocks(api_for_blocks).await {
            eprintln!("block subscription task failed: {e}");
        }
    });
    println!("⛓🗄️ fetching onchain history from indexer");
    get_history(&everybody).await.unwrap();
    println!("⛓ Listening to System.Remark Extrinsics in new finalized blocks...");

    println!("*********** SETUP PHASE **************" );
    // Every voter publishes their X25519 public key on-chain using System.Remark
    let _ = join_all(everybody.iter().map(|signer|
        send_remark(&api, &signer.sr25519_keypair,
                    CorevoRemark::V1(CorevoRemarkV1 {
                        context: CorevoContext::String(CONTEXT.into()),
                        msg: CorevoMessage::AnnounceOwnPubKey(signer.x25519_public.to_bytes())
                    }).into()))).await;
    println!("*********** INVITE PHASE **************" );
    let common_salt = random::<[u8; 32]>();
    println!("common salt: {}", hex::encode(common_salt.encode()));
    let ciphertext = encrypt_for_recipient(&proposer.x25519_secret, &voter_b.x25519_public, &common_salt.into()).unwrap();
    println!("    verify: Encrypted message from proposer to voter B: 0x{}", hex::encode(ciphertext.encode()));
    let plaintext_at_voter_b = decrypt_from_sender(&voter_b.x25519_secret, &proposer.x25519_public, ciphertext.as_slice()).unwrap();
    println!("    verify: Decrypted message at voter B: 0x{}", hex::encode(plaintext_at_voter_b.encode()));

    // send encrypted common salt to everybody else (and self, for persistence). Send sequentially to avoid nonce race.
    for account in everybody.clone() {
        send_remark(&api, &proposer.sr25519_keypair, CorevoRemark::V1(CorevoRemarkV1 {
            context: CorevoContext::String(CONTEXT.into()),
            msg: CorevoMessage::InviteVoter(
                account.sr25519_keypair.public_key().to_account_id(),
                encrypt_for_recipient(&proposer.x25519_secret, &account.x25519_public, &common_salt.into()).unwrap()
            )
        }).into()).await?
    }

    println!("*********** COMMIT PHASE ************" );
    let mut everybody_votes = HashMap::<[u8; 32], CorevoVoteAndSalt>::new();
    // Every voter publishes their commitment
    let _ = join_all(everybody.clone().iter().map(|signer| {
        let vote = CorevoVote::Aye;
        let onetime_salt = random::<Salt>();
        let vote_and_salt = CorevoVoteAndSalt { vote, onetime_salt };
        everybody_votes.insert(signer.sr25519_keypair.public_key().0, vote_and_salt.clone());
        let commitment = vote_and_salt.commit(Some(common_salt));
        println!("🗳 Voter {} commits to vote {:?} with onetime_salt 0x{} resulting in commitment 0x{}",
            signer.sr25519_keypair.public_key().to_account_id(),
            vote,
            hex::encode(onetime_salt.encode()),
            hex::encode(commitment.encode())
        );
        send_remark(&api, &signer.sr25519_keypair,
                    CorevoRemark::V1(CorevoRemarkV1 {
                        context: CorevoContext::String(CONTEXT.into()),
                        msg: CorevoMessage::Commit(commitment,
                        encrypt_for_recipient(&signer.x25519_secret, &signer.x25519_public,
                            &vote_and_salt.encode()).unwrap_or_default())
                    }).into())
    })).await;

    println!("*********** REVEAL PHASE ************" );
    // Every voter reveals their vote
    let _ = join_all(everybody.clone().iter().map(|signer| {
        let vote_and_salt = everybody_votes.get(&signer.sr25519_keypair.public_key().0).unwrap();
        send_remark(&api, &signer.sr25519_keypair,
                    CorevoRemark::V1(CorevoRemarkV1 {
                        context: CorevoContext::String(CONTEXT.into()),
                        msg: CorevoMessage::RevealOneTimeSalt(vote_and_salt.onetime_salt)
                    }).into())
    })).await;

    listener_handle.await?;
    Ok(())
}

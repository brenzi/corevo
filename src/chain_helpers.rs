use codec::{Decode, Encode};
use subxt::OnlineClient;
use subxt::utils::{AccountId32, MultiAddress};
use subxt_signer::sr25519::Keypair;
use crate::{assethub, AssetHubConfig};
use crate::primitives::{CorevoMessage, CorevoRemark, PrefixedCorevoRemark};

pub async fn listen_to_blocks(api: OnlineClient<AssetHubConfig>) -> Result<(), Box<dyn std::error::Error>> {
    let mut blocks = api.blocks().subscribe_finalized().await?;
    while let Some(block) = blocks.next().await {
        let block = block?;
        let extrinsics = block.extrinsics().await?;
        for ext in extrinsics.iter() {
            if let Some(remark) = ext.as_extrinsic::<assethub::system::calls::types::Remark>()? {
                println!("⛓ Remark in block {}: 0x{}", block.number(), hex::encode(remark.remark.clone()));
                if let Some(address_bytes) = ext.address_bytes() {
                    if let Ok(MultiAddress::Id(sender)) = MultiAddress::<AccountId32, ()>::decode(&mut &address_bytes[..]) {
                        println!("⛓    signed by {}", sender);
                    }
                }
                if let Ok(corevo_remark) = PrefixedCorevoRemark::decode(&mut remark.remark.as_slice()) {
                    match corevo_remark.0 {
                        CorevoRemark::V1(corevo_remark_v1) => {
                            println!("⛓    It's a Corevo V1 remark for context: 0x{}", hex::encode(corevo_remark_v1.context));
                            match corevo_remark_v1.msg {
                                CorevoMessage::AnnounceOwnPubKey(pubkey_bytes) => {
                                    println!("⛓      AnnounceOwnPubKey: 0x{}", hex::encode(pubkey_bytes));
                                }
                                CorevoMessage::InviteVoter(account, common_salt_enc) => {
                                    println!("⛓      InviteVoter: {} with encrypted common salt 0x{}", account, hex::encode(common_salt_enc.encode()));
                                }
                                CorevoMessage::Commit(commitment, encrypted_vote_and_salt) => {
                                    println!("⛓      Commit: commitment 0x{}", hex::encode(commitment.encode()));
                                    println!("⛓              encrypted_vote_and_salt: 0x{}", hex::encode(encrypted_vote_and_salt.encode()));
                                }
                                CorevoMessage::RevealOneTimeSalt(onetime_salt) => {
                                    println!("⛓      RevealOneTimeSalt: 0x{}", hex::encode(onetime_salt.encode()));
                                }
                            }
                        }
                    }
                } else {
                    println!("⛓    not a Corevo Remark");
                }
            }
        }
    }
    Ok(())
}

pub async fn send_remark(api: &OnlineClient<AssetHubConfig>, signer: &Keypair, remark: PrefixedCorevoRemark) -> Result<(), Box<dyn std::error::Error>> {
    let remark_bytes = remark.encode();

    let remark_tx = assethub::tx()
        .system()
        .remark(remark_bytes);
    let _events = api
        .tx()
        .sign_and_submit_then_watch_default(&remark_tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    println!("📨 Remark sent by {}: {:?}", signer.public_key().to_account_id(), remark);
    Ok(())
}


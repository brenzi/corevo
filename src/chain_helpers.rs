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
                    if let CorevoRemark::V1(corevo_remark_v1) = corevo_remark.0 {
                        println!("⛓    CorevoV1 remark {}", corevo_remark_v1);
                    } else {
                        println!("⛓    Corevo Remark of unknown version");
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

/// Hex encodes given data and preappends a "0x".
pub fn hex_encode(data: &[u8]) -> String {
    let mut hex_str = hex::encode(data);
    hex_str.insert_str(0, "0x");
    hex_str
}

/// Helper method for decoding `0x`-prefixed hex.
pub fn decode_hex<T: AsRef<[u8]>>(message: T) -> Result<Vec<u8>, hex::FromHexError> {
    let message = message.as_ref();
    let message = match message {
        [b'0', b'x', hex_value @ ..] => hex_value,
        _ => message,
    };

    let decoded_message = hex::decode(message)?;
    Ok(decoded_message)
}

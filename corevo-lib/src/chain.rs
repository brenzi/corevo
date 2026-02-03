use codec::Encode;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::{CorevoError, Result};
use crate::primitives::PrefixedCorevoRemark;

// Generate the runtime API from metadata
#[subxt::subxt(runtime_metadata_path = "../kusama_asset_hub_metadata.scale")]
pub mod assethub {}

/// Type alias for the chain configuration
pub type AssetHubConfig = PolkadotConfig;

/// Client for interacting with the Substrate chain
pub struct ChainClient {
    api: OnlineClient<AssetHubConfig>,
}

impl ChainClient {
    /// Connect to a Substrate chain
    pub async fn connect(url: &str) -> Result<Self> {
        let api = OnlineClient::<AssetHubConfig>::from_url(url)
            .await
            .map_err(|e| CorevoError::ChainConnection(e.to_string()))?;
        Ok(Self { api })
    }

    /// Connect using the configuration
    pub async fn from_config(config: &Config) -> Result<Self> {
        Self::connect(&config.chain_url).await
    }

    /// Get the underlying API client (for advanced operations)
    pub fn api(&self) -> &OnlineClient<AssetHubConfig> {
        &self.api
    }

    /// Check account balance on chain
    pub async fn get_account_balance(
        &self,
        account_id: &subxt::utils::AccountId32,
    ) -> Result<u128> {
        let storage = self.api.storage().at_latest().await?;
        let account_info = storage
            .fetch(&assethub::storage().system().account(account_id.clone()))
            .await?
            .ok_or_else(|| CorevoError::AccountNotFound(account_id.to_string()))?;
        Ok(account_info.data.free)
    }

    /// Send a CoReVo remark transaction
    pub async fn send_remark(
        &self,
        signer: &Keypair,
        remark: PrefixedCorevoRemark,
    ) -> Result<()> {
        let remark_bytes = remark.encode();

        let remark_tx = assethub::tx().system().remark(remark_bytes);
        self.api
            .tx()
            .sign_and_submit_then_watch_default(&remark_tx, signer)
            .await?
            .wait_for_finalized_success()
            .await?;

        log::info!(
            "Remark sent by {}: {:?}",
            signer.public_key().to_account_id(),
            remark
        );
        Ok(())
    }

    /// Subscribe to finalized blocks and receive CoReVo remarks
    ///
    /// Returns a receiver channel that yields (sender, remark) tuples
    pub fn subscribe_remarks(
        &self,
    ) -> Result<mpsc::Receiver<(subxt::utils::AccountId32, crate::primitives::CorevoRemarkV1)>> {
        use codec::Decode;
        use subxt::utils::{AccountId32, MultiAddress};

        let (tx, rx) = mpsc::channel(100);
        let api = self.api.clone();

        tokio::spawn(async move {
            let mut blocks = match api.blocks().subscribe_finalized().await {
                Ok(b) => b,
                Err(e) => {
                    log::error!("Failed to subscribe to blocks: {}", e);
                    return;
                }
            };

            while let Some(block_result) = blocks.next().await {
                let block = match block_result {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!("Block error: {}", e);
                        continue;
                    }
                };

                let extrinsics = match block.extrinsics().await {
                    Ok(e) => e,
                    Err(e) => {
                        log::error!("Extrinsics error: {}", e);
                        continue;
                    }
                };

                for ext in extrinsics.iter() {
                    if let Ok(Some(remark)) =
                        ext.as_extrinsic::<assethub::system::calls::types::Remark>()
                    {
                        // Extract sender
                        let sender = ext.address_bytes().and_then(|addr| {
                            MultiAddress::<AccountId32, ()>::decode(&mut &addr[..])
                                .ok()
                                .and_then(|ma| match ma {
                                    MultiAddress::Id(id) => Some(id),
                                    _ => None,
                                })
                        });

                        // Try to decode as CoReVo remark
                        if let Ok(prefixed) = crate::primitives::PrefixedCorevoRemark::decode(
                            &mut remark.remark.as_slice(),
                        ) {
                            #[allow(irrefutable_let_patterns)]
                            if let crate::primitives::CorevoRemark::V1(remark_v1) = prefixed.0 {
                                if let Some(sender_id) = sender {
                                    if tx.send((sender_id, remark_v1)).await.is_err() {
                                        // Receiver dropped, stop subscription
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(rx)
    }
}

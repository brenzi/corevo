use async_trait::async_trait;
use codec::Encode;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::{CorevoError, Result};
use crate::primitives::{CorevoRemarkV1, PrefixedCorevoRemark, hex_encode};

// Generate the runtime API from metadata
#[subxt::subxt(runtime_metadata_path = "../kusama_asset_hub_metadata.scale")]
pub mod assethub {}

/// Type alias for the chain configuration
pub type AssetHubConfig = PolkadotConfig;

/// Trait for chain interactions - enables mocking in tests
#[async_trait]
pub trait ChainApi: Send + Sync {
    /// Check account balance on chain
    async fn get_account_balance(&self, account_id: &subxt::utils::AccountId32) -> Result<u128>;

    /// Send a CoReVo remark transaction
    async fn send_remark(&self, signer: &Keypair, remark: PrefixedCorevoRemark) -> Result<()>;

    /// Send multiple CoReVo remark transactions with proper nonce sequencing
    async fn send_remarks_batch(
        &self,
        signer: &Keypair,
        remarks: Vec<PrefixedCorevoRemark>,
    ) -> Result<()>;

    /// Subscribe to finalized blocks and receive CoReVo remarks
    ///
    /// Returns a receiver channel that yields (sender, remark) tuples
    fn subscribe_remarks(
        &self,
    ) -> Result<mpsc::Receiver<(subxt::utils::AccountId32, CorevoRemarkV1)>>;
}

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

    /// Send a CoReVo remark transaction and wait for block inclusion
    /// This waits for the tx to be included in a block (not finalized) which is
    /// faster and sufficient for nonce sequencing in batch operations.
    pub async fn send_remark(&self, signer: &Keypair, remark: PrefixedCorevoRemark) -> Result<()> {
        let remark_bytes = remark.encode();
        log::debug!(
            "Sending remark extrinsic: call_data=0x{}",
            hex_encode(&remark_bytes)
        );
        let remark_tx = assethub::tx().system().remark(remark_bytes);

        let mut progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&remark_tx, signer)
            .await?;

        // Wait for the transaction to be included in a block (faster than finalization)
        while let Some(status) = progress.next().await {
            match status? {
                subxt::tx::TxStatus::InBestBlock(in_block) => {
                    // Check for success
                    in_block.wait_for_success().await?;
                    log::info!(
                        "Remark sent by {}: {:?}",
                        signer.public_key().to_account_id(),
                        remark
                    );
                    return Ok(());
                }
                subxt::tx::TxStatus::InFinalizedBlock(in_block) => {
                    // Also acceptable - tx is finalized
                    in_block.wait_for_success().await?;
                    log::info!(
                        "Remark sent by {}: {:?}",
                        signer.public_key().to_account_id(),
                        remark
                    );
                    return Ok(());
                }
                subxt::tx::TxStatus::Error { message } => {
                    return Err(CorevoError::Transaction(format!(
                        "Transaction error: {}",
                        message
                    )));
                }
                subxt::tx::TxStatus::Invalid { message } => {
                    return Err(CorevoError::Transaction(format!(
                        "Invalid transaction: {}",
                        message
                    )));
                }
                subxt::tx::TxStatus::Dropped { message } => {
                    return Err(CorevoError::Transaction(format!(
                        "Transaction dropped: {}",
                        message
                    )));
                }
                // Continue waiting for other statuses (Validated, Broadcasted, etc.)
                _ => continue,
            }
        }

        Err(CorevoError::Transaction(
            "Transaction stream ended unexpectedly".to_string(),
        ))
    }

    /// Send multiple CoReVo remark transactions with proper nonce sequencing
    /// This method manages nonces explicitly to avoid race conditions
    pub async fn send_remarks_batch(
        &self,
        signer: &Keypair,
        remarks: Vec<PrefixedCorevoRemark>,
    ) -> Result<()> {
        use subxt::config::DefaultExtrinsicParamsBuilder;

        if remarks.is_empty() {
            return Ok(());
        }

        let account_id = signer.public_key().to_account_id();

        // Get the starting nonce
        let mut nonce = self.api.tx().account_nonce(&account_id).await?;

        for remark in remarks {
            let remark_bytes = remark.encode();
            log::debug!(
                "Sending remark extrinsic (nonce {}): call_data=0x{}",
                nonce,
                hex_encode(&remark_bytes)
            );
            let remark_tx = assethub::tx().system().remark(remark_bytes);

            // Build params with explicit nonce
            let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

            let mut progress = self
                .api
                .tx()
                .create_signed(&remark_tx, signer, params)
                .await?
                .submit_and_watch()
                .await?;

            // Wait for the transaction to be included in a block
            let mut success = false;
            while let Some(status) = progress.next().await {
                match status? {
                    subxt::tx::TxStatus::InBestBlock(in_block) => {
                        in_block.wait_for_success().await?;
                        log::info!(
                            "Remark sent by {} (nonce {}): {:?}",
                            account_id,
                            nonce,
                            remark
                        );
                        success = true;
                        break;
                    }
                    subxt::tx::TxStatus::InFinalizedBlock(in_block) => {
                        in_block.wait_for_success().await?;
                        log::info!(
                            "Remark sent by {} (nonce {}): {:?}",
                            account_id,
                            nonce,
                            remark
                        );
                        success = true;
                        break;
                    }
                    subxt::tx::TxStatus::Error { message } => {
                        return Err(CorevoError::Transaction(format!(
                            "Transaction error: {}",
                            message
                        )));
                    }
                    subxt::tx::TxStatus::Invalid { message } => {
                        return Err(CorevoError::Transaction(format!(
                            "Invalid transaction: {}",
                            message
                        )));
                    }
                    subxt::tx::TxStatus::Dropped { message } => {
                        return Err(CorevoError::Transaction(format!(
                            "Transaction dropped: {}",
                            message
                        )));
                    }
                    _ => continue,
                }
            }

            if !success {
                return Err(CorevoError::Transaction(
                    "Transaction stream ended unexpectedly".to_string(),
                ));
            }

            // Increment nonce for next transaction
            nonce += 1;
        }

        Ok(())
    }

    /// Subscribe to finalized blocks and receive CoReVo remarks (internal implementation)
    fn subscribe_remarks_impl(
        &self,
    ) -> Result<mpsc::Receiver<(subxt::utils::AccountId32, CorevoRemarkV1)>> {
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
                            if let (crate::primitives::CorevoRemark::V1(remark_v1), Some(sender_id)) =
                                (prefixed.0, sender)
                                && tx.send((sender_id, remark_v1)).await.is_err()
                            {
                                // Receiver dropped, stop subscription
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(rx)
    }
}

#[async_trait]
impl ChainApi for ChainClient {
    async fn get_account_balance(&self, account_id: &subxt::utils::AccountId32) -> Result<u128> {
        self.get_account_balance(account_id).await
    }

    async fn send_remark(&self, signer: &Keypair, remark: PrefixedCorevoRemark) -> Result<()> {
        self.send_remark(signer, remark).await
    }

    async fn send_remarks_batch(
        &self,
        signer: &Keypair,
        remarks: Vec<PrefixedCorevoRemark>,
    ) -> Result<()> {
        self.send_remarks_batch(signer, remarks).await
    }

    fn subscribe_remarks(
        &self,
    ) -> Result<mpsc::Receiver<(subxt::utils::AccountId32, CorevoRemarkV1)>> {
        self.subscribe_remarks_impl()
    }
}

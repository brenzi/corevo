//! CoReVo Library - Commit-Reveal Voting on Substrate
//!
//! This library provides functionality for confidential group voting
//! on Substrate-based blockchains using System.Remark extrinsics.
//!
//! # Overview
//!
//! CoReVo implements a commit-reveal voting scheme where:
//! 1. Voters commit to their votes using cryptographic hashes
//! 2. Votes remain private until the reveal phase
//! 3. All data is stored on-chain via System.Remark
//!
//! # Example
//!
//! ```ignore
//! use corevo_lib::{Config, ChainClient, HistoryQuery, derive_account_from_uri};
//!
//! let config = Config::default();
//! let client = ChainClient::from_config(&config).await?;
//! let account = derive_account_from_uri("//Alice")?;
//!
//! // Query voting history
//! let history = HistoryQuery::new(&config)
//!     .with_known_accounts(vec![account])
//!     .execute()
//!     .await?;
//! ```

pub mod chain;
pub mod config;
pub mod crypto;
pub mod error;
pub mod indexer;
pub mod primitives;

// Re-export main types for convenience
pub use chain::{ChainApi, ChainClient};
pub use config::Config;
pub use crypto::{
    ChainTokenInfo, SS58_PREFIX_KUSAMA, SS58_PREFIX_POLKADOT, SS58_PREFIX_SUBSTRATE,
    decrypt_from_sender, derive_account_from_uri, derive_address_from_uri, encode_ss58,
    encrypt_for_recipient, format_account_ss58, format_balance, ss58_prefix_for_chain,
    token_info_for_chain,
};
pub use error::{CorevoError, Result};
pub use indexer::{
    ContextSummary, HashableAccountId, HistoryQuery, MongoRemarkRepository, RemarkAggregation,
    RemarkRecord, RemarkRepository, VoteStatus, VotingHistory, aggregate_remarks,
    build_voting_history, decrypt_common_salts, reveal_votes,
};
pub use primitives::{
    COREVO_REMARK_PREFIX, Commitment, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1,
    CorevoVote, CorevoVoteAndSalt, PrefixedCorevoRemark, PublicKeyForEncryption, Salt,
    VotingAccount,
};

// Re-export subxt types that are commonly needed
pub use subxt::utils::AccountId32;

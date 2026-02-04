use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use codec::Decode;
use futures::TryStreamExt;
use mongodb::{
    bson::{doc, Bson},
    options::ClientOptions,
    Client,
};
use subxt::utils::AccountId32;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::config::Config;
use crate::crypto::decrypt_from_sender;
use crate::error::Result;
use crate::primitives::{
    decode_hex, Commitment, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1,
    CorevoVote, CorevoVoteAndSalt, PrefixedCorevoRemark, PublicKeyForEncryption, Salt,
    VotingAccount,
};

/// Wrapper for AccountId32 that implements Hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashableAccountId(pub AccountId32);

impl std::hash::Hash for HashableAccountId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state);
    }
}

impl From<AccountId32> for HashableAccountId {
    fn from(account_id: AccountId32) -> Self {
        HashableAccountId(account_id)
    }
}

impl std::fmt::Display for HashableAccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Configuration for a voting context
#[derive(Clone, Debug)]
pub struct ContextConfig {
    pub proposer: AccountId32,
    pub voters: HashSet<HashableAccountId>,
    /// Decrypted common salts (multiple invitation rounds possible)
    pub common_salts: Vec<Salt>,
    /// Encrypted common salts per voter
    pub encrypted_common_salts: HashMap<HashableAccountId, Vec<Vec<u8>>>,
}

/// Commit data for later verification
#[derive(Clone, Debug)]
pub struct CommitData {
    pub commitment: Commitment,
    pub encrypted_vote_and_salt: Vec<u8>,
}

/// Status of a participant's vote
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteStatus {
    Committed(Commitment),
    Revealed(std::result::Result<CorevoVote, &'static str>),
    RevealedWithoutCommitment,
}

/// Summary of a voting context
#[derive(Clone, Debug)]
pub struct ContextSummary {
    pub context: CorevoContext,
    pub proposer: AccountId32,
    pub voters: HashSet<HashableAccountId>,
    pub votes: HashMap<HashableAccountId, VoteStatus>,
    pub common_salts: Vec<Salt>,
}

/// Result of history query
#[derive(Clone, Debug)]
pub struct VotingHistory {
    pub contexts: HashMap<CorevoContext, ContextSummary>,
    pub voter_pubkeys: HashMap<HashableAccountId, PublicKeyForEncryption>,
}

/// Builder for querying voting history from MongoDB
pub struct HistoryQuery {
    config: Config,
    filter_context: Option<CorevoContext>,
    known_accounts: Vec<VotingAccount>,
}

impl HistoryQuery {
    pub fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
            filter_context: None,
            known_accounts: Vec::new(),
        }
    }

    /// Filter to a specific voting context
    pub fn with_context(mut self, ctx: CorevoContext) -> Self {
        self.filter_context = Some(ctx);
        self
    }

    /// Add known accounts for decryption
    pub fn with_known_accounts(mut self, accounts: Vec<VotingAccount>) -> Self {
        self.known_accounts = accounts;
        self
    }

    /// Execute the query and return voting history
    pub async fn execute(&self) -> Result<VotingHistory> {
        // Build lookup maps from known accounts
        let mut known_secrets: HashMap<HashableAccountId, StaticSecret> = HashMap::new();
        let mut known_pubkeys_from_secrets: HashMap<HashableAccountId, X25519PublicKey> =
            HashMap::new();

        for account in &self.known_accounts {
            let account_id = account.sr25519_keypair.public_key().to_account_id();
            known_secrets.insert(
                HashableAccountId(account_id.clone()),
                account.x25519_secret.clone(),
            );
            known_pubkeys_from_secrets
                .insert(HashableAccountId(account_id), account.x25519_public);
        }

        let mut voter_pubkeys: HashMap<HashableAccountId, PublicKeyForEncryption> = HashMap::new();
        let mut context_configs: HashMap<CorevoContext, ContextConfig> = HashMap::new();
        let mut context_votes: HashMap<CorevoContext, HashMap<HashableAccountId, VoteStatus>> =
            HashMap::new();
        let mut context_commits: HashMap<CorevoContext, HashMap<HashableAccountId, CommitData>> =
            HashMap::new();
        let mut context_revealed_salts: HashMap<CorevoContext, HashMap<HashableAccountId, Salt>> =
            HashMap::new();

        // Connect to MongoDB
        let mut client_options = ClientOptions::parse(&self.config.mongodb_uri).await?;
        client_options.app_name = Some("corevo-lib".to_string());
        let client = Client::with_options(client_options)?;

        let db = client.database(&self.config.mongodb_db);
        let coll = db.collection::<mongodb::bson::Document>("extrinsics");

        // Query for CoReVo-prefixed remarks
        let filter = doc! {
            "method": "remark",
            "args.remark": { "$regex": "^0xcc00ee", "$options": "i" }
        };

        let mut cursor = coll.find(filter).await?;

        // Process all remarks
        while let Some(doc) = cursor.try_next().await? {
            let remark = doc
                .get_document("args")
                .ok()
                .and_then(|args| args.get("remark"))
                .and_then(|v| match v {
                    Bson::String(s) => Some(s.as_str()),
                    _ => None,
                });

            let Some(sender) = doc
                .get_document("signer")
                .ok()
                .and_then(|signer_doc| signer_doc.get_str("Id").ok())
                .and_then(|s| AccountId32::from_str(s).ok())
            else {
                continue;
            };

            let Some(remark_hex) = remark else {
                continue;
            };

            let Ok(remark_bytes) = decode_hex(remark_hex) else {
                continue;
            };

            let Ok(prefixed) = PrefixedCorevoRemark::decode(&mut remark_bytes.as_slice()) else {
                continue;
            };

            #[allow(irrefutable_let_patterns)]
            let CorevoRemark::V1(CorevoRemarkV1 { context, msg }) = prefixed.0
            else {
                continue;
            };

            // Apply context filter if specified
            if let Some(ref filter_ctx) = self.filter_context {
                if &context != filter_ctx {
                    continue;
                }
            }

            match msg {
                CorevoMessage::AnnounceOwnPubKey(pubkey) => {
                    voter_pubkeys.insert(sender.clone().into(), pubkey);
                }
                CorevoMessage::InviteVoter(voter, encrypted_common_salt) => {
                    let config = context_configs.entry(context.clone()).or_insert_with(|| {
                        ContextConfig {
                            proposer: sender.clone(),
                            voters: HashSet::new(),
                            common_salts: Vec::new(),
                            encrypted_common_salts: HashMap::new(),
                        }
                    });
                    config.voters.insert(HashableAccountId(voter.clone()));
                    config
                        .encrypted_common_salts
                        .entry(HashableAccountId(voter))
                        .or_default()
                        .push(encrypted_common_salt);
                }
                CorevoMessage::Commit(commitment, encrypted_vote_and_salt) => {
                    context_votes
                        .entry(context.clone())
                        .or_default()
                        .insert(
                            HashableAccountId(sender.clone()),
                            VoteStatus::Committed(commitment),
                        );
                    context_commits
                        .entry(context.clone())
                        .or_default()
                        .insert(
                            HashableAccountId(sender.clone()),
                            CommitData {
                                commitment,
                                encrypted_vote_and_salt,
                            },
                        );
                }
                CorevoMessage::RevealOneTimeSalt(onetime_salt) => {
                    context_revealed_salts
                        .entry(context.clone())
                        .or_default()
                        .insert(HashableAccountId(sender.clone()), onetime_salt);

                    let votes = context_votes.entry(context.clone()).or_default();
                    match votes.get(&HashableAccountId(sender.clone())) {
                        Some(VoteStatus::Committed(_)) => {
                            votes.insert(
                                HashableAccountId(sender.clone()),
                                VoteStatus::Revealed(Err("Pending brute-force")),
                            );
                        }
                        None => {
                            votes.insert(
                                HashableAccountId(sender),
                                VoteStatus::RevealedWithoutCommitment,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        // Phase 2: Decrypt common salts using known account secrets
        for (_context, config) in context_configs.iter_mut() {
            let mut seen_salts: HashSet<[u8; 32]> = HashSet::new();
            let proposer_key = HashableAccountId(config.proposer.clone());

            // Method 1: If we have the proposer's secret, decrypt all invites
            if let Some(proposer_secret) = known_secrets.get(&proposer_key) {
                for (voter, encrypted_salts) in config.encrypted_common_salts.iter() {
                    let voter_pubkey = voter_pubkeys
                        .get(voter)
                        .map(|pk| X25519PublicKey::from(*pk))
                        .or_else(|| known_pubkeys_from_secrets.get(voter).cloned());

                    if let Some(voter_pub) = voter_pubkey {
                        for encrypted_salt in encrypted_salts {
                            if let Ok(decrypted) =
                                decrypt_from_sender(proposer_secret, &voter_pub, encrypted_salt)
                            {
                                if decrypted.len() == 32 {
                                    let mut salt = [0u8; 32];
                                    salt.copy_from_slice(&decrypted);
                                    if seen_salts.insert(salt) {
                                        config.common_salts.push(salt);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Method 2: If we have a voter's secret, decrypt their own invite
            // (works even if we're not the proposer)
            let proposer_pubkey = voter_pubkeys
                .get(&proposer_key)
                .map(|pk| X25519PublicKey::from(*pk));

            if let Some(proposer_pub) = proposer_pubkey {
                for (voter, encrypted_salts) in config.encrypted_common_salts.iter() {
                    // Check if we have this voter's secret
                    if let Some(voter_secret) = known_secrets.get(voter) {
                        for encrypted_salt in encrypted_salts {
                            // Decrypt using voter's secret + proposer's public key
                            if let Ok(decrypted) =
                                decrypt_from_sender(voter_secret, &proposer_pub, encrypted_salt)
                            {
                                if decrypted.len() == 32 {
                                    let mut salt = [0u8; 32];
                                    salt.copy_from_slice(&decrypted);
                                    if seen_salts.insert(salt) {
                                        config.common_salts.push(salt);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: Reveal votes by brute-forcing
        for (context, config) in context_configs.iter() {
            if config.common_salts.is_empty() {
                continue;
            }

            let Some(commits) = context_commits.get(context) else {
                continue;
            };

            let Some(revealed_salts) = context_revealed_salts.get(context) else {
                continue;
            };

            let Some(votes) = context_votes.get_mut(context) else {
                continue;
            };

            for (voter, commit_data) in commits.iter() {
                if let Some(onetime_salt) = revealed_salts.get(voter) {
                    let mut found_vote = None;
                    for common_salt in &config.common_salts {
                        if let Some(vote) = CorevoVoteAndSalt::reveal_vote_by_bruteforce(
                            *onetime_salt,
                            *common_salt,
                            commit_data.commitment,
                        ) {
                            found_vote = Some(vote);
                            break;
                        }
                    }
                    if let Some(vote) = found_vote {
                        votes.insert(voter.clone(), VoteStatus::Revealed(Ok(vote)));
                    } else {
                        votes.insert(
                            voter.clone(),
                            VoteStatus::Revealed(Err("No vote matched commitment")),
                        );
                    }
                }
            }
        }

        // Build result
        let mut contexts = HashMap::new();
        for (context, config) in context_configs {
            let votes = context_votes.remove(&context).unwrap_or_default();
            contexts.insert(
                context.clone(),
                ContextSummary {
                    context,
                    proposer: config.proposer,
                    voters: config.voters,
                    votes,
                    common_salts: config.common_salts,
                },
            );
        }

        Ok(VotingHistory {
            contexts,
            voter_pubkeys,
        })
    }
}

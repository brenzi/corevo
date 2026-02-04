use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use async_trait::async_trait;
use codec::Decode;
use futures::TryStreamExt;
use mongodb::{
    Client,
    bson::{Bson, doc},
    options::ClientOptions,
};
use subxt::utils::AccountId32;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::config::Config;
use crate::crypto::decrypt_from_sender;
use crate::error::Result;
use crate::primitives::{
    Commitment, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1, CorevoVote,
    CorevoVoteAndSalt, PrefixedCorevoRemark, PublicKeyForEncryption, Salt, VotingAccount,
    decode_hex,
};

/// Wrapper for AccountId32 that implements Hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashableAccountId(pub AccountId32);

impl std::hash::Hash for HashableAccountId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.0.hash(state);
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

/// A remark record from the database
#[derive(Clone, Debug)]
pub struct RemarkRecord {
    pub sender: AccountId32,
    pub remark: CorevoRemarkV1,
}

/// Trait for fetching remarks from a data source - enables mocking in tests
#[async_trait]
pub trait RemarkRepository: Send + Sync {
    /// Fetch all CoReVo remarks, optionally filtered by context
    async fn fetch_remarks(
        &self,
        filter_context: Option<&CorevoContext>,
    ) -> Result<Vec<RemarkRecord>>;
}

/// MongoDB implementation of RemarkRepository
pub struct MongoRemarkRepository {
    config: Config,
}

impl MongoRemarkRepository {
    pub fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait]
impl RemarkRepository for MongoRemarkRepository {
    async fn fetch_remarks(
        &self,
        filter_context: Option<&CorevoContext>,
    ) -> Result<Vec<RemarkRecord>> {
        let mut client_options = ClientOptions::parse(&self.config.mongodb_uri).await?;
        client_options.app_name = Some("corevo-lib".to_string());
        let client = Client::with_options(client_options)?;

        let db = client.database(&self.config.mongodb_db);
        let coll = db.collection::<mongodb::bson::Document>("extrinsics");

        let filter = doc! {
            "method": "remark",
            "args.remark": { "$regex": "^0xcc00ee", "$options": "i" }
        };

        let mut cursor = coll.find(filter).await?;
        let mut records = Vec::new();

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
            let CorevoRemark::V1(remark_v1) = prefixed.0 else {
                continue;
            };

            // Apply context filter if specified
            if filter_context.is_some_and(|filter_ctx| remark_v1.context != *filter_ctx) {
                continue;
            }

            records.push(RemarkRecord {
                sender,
                remark: remark_v1,
            });
        }

        Ok(records)
    }
}

/// Intermediate aggregation of remarks before decryption/revelation
#[derive(Clone, Debug, Default)]
pub struct RemarkAggregation {
    pub voter_pubkeys: HashMap<HashableAccountId, PublicKeyForEncryption>,
    pub context_configs: HashMap<CorevoContext, ContextConfig>,
    pub context_votes: HashMap<CorevoContext, HashMap<HashableAccountId, VoteStatus>>,
    pub context_commits: HashMap<CorevoContext, HashMap<HashableAccountId, CommitData>>,
    pub context_revealed_salts: HashMap<CorevoContext, HashMap<HashableAccountId, Salt>>,
}

/// Pure function: Aggregate remarks into structured data
///
/// Phase 1 of the history processing pipeline - no decryption, just categorization.
pub fn aggregate_remarks(remarks: Vec<RemarkRecord>) -> RemarkAggregation {
    let mut agg = RemarkAggregation::default();

    for RemarkRecord { sender, remark } in remarks {
        let CorevoRemarkV1 { context, msg } = remark;

        match msg {
            CorevoMessage::AnnounceOwnPubKey(pubkey) => {
                agg.voter_pubkeys.insert(sender.clone().into(), pubkey);
            }
            CorevoMessage::InviteVoter(voter, encrypted_common_salt) => {
                let config = agg
                    .context_configs
                    .entry(context.clone())
                    .or_insert_with(|| ContextConfig {
                        proposer: sender.clone(),
                        voters: HashSet::new(),
                        common_salts: Vec::new(),
                        encrypted_common_salts: HashMap::new(),
                    });
                config.voters.insert(HashableAccountId(voter.clone()));
                config
                    .encrypted_common_salts
                    .entry(HashableAccountId(voter))
                    .or_default()
                    .push(encrypted_common_salt);
            }
            CorevoMessage::Commit(commitment, encrypted_vote_and_salt) => {
                agg.context_votes
                    .entry(context.clone())
                    .or_default()
                    .insert(
                        HashableAccountId(sender.clone()),
                        VoteStatus::Committed(commitment),
                    );
                agg.context_commits
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
                agg.context_revealed_salts
                    .entry(context.clone())
                    .or_default()
                    .insert(HashableAccountId(sender.clone()), onetime_salt);

                let votes = agg.context_votes.entry(context.clone()).or_default();
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

    agg
}

/// Pure function: Decrypt common salts using known account secrets
///
/// Phase 2 of the history processing pipeline.
pub fn decrypt_common_salts(
    agg: &mut RemarkAggregation,
    known_secrets: &HashMap<HashableAccountId, StaticSecret>,
    known_pubkeys_from_secrets: &HashMap<HashableAccountId, X25519PublicKey>,
) {
    for (_context, config) in agg.context_configs.iter_mut() {
        let mut seen_salts: HashSet<[u8; 32]> = HashSet::new();
        let proposer_key = HashableAccountId(config.proposer.clone());

        // Method 1: If we have the proposer's secret, decrypt all invites
        if let Some(proposer_secret) = known_secrets.get(&proposer_key) {
            for (voter, encrypted_salts) in config.encrypted_common_salts.iter() {
                let voter_pubkey = agg
                    .voter_pubkeys
                    .get(voter)
                    .map(|pk| X25519PublicKey::from(*pk))
                    .or_else(|| known_pubkeys_from_secrets.get(voter).cloned());

                if let Some(voter_pub) = voter_pubkey {
                    for encrypted_salt in encrypted_salts {
                        if let Ok(decrypted) =
                            decrypt_from_sender(proposer_secret, &voter_pub, encrypted_salt)
                            && let Ok(salt) = <[u8; 32]>::try_from(decrypted.as_slice())
                            && seen_salts.insert(salt)
                        {
                            config.common_salts.push(salt);
                        }
                    }
                }
            }
        }

        // Method 2: If we have a voter's secret, decrypt their own invite
        let proposer_pubkey = agg
            .voter_pubkeys
            .get(&proposer_key)
            .map(|pk| X25519PublicKey::from(*pk));

        if let Some(proposer_pub) = proposer_pubkey {
            for (voter, encrypted_salts) in config.encrypted_common_salts.iter() {
                if let Some(voter_secret) = known_secrets.get(voter) {
                    for encrypted_salt in encrypted_salts {
                        if let Ok(decrypted) =
                            decrypt_from_sender(voter_secret, &proposer_pub, encrypted_salt)
                            && let Ok(salt) = <[u8; 32]>::try_from(decrypted.as_slice())
                            && seen_salts.insert(salt)
                        {
                            config.common_salts.push(salt);
                        }
                    }
                }
            }
        }
    }
}

/// Pure function: Reveal votes by brute-forcing commitments
///
/// Phase 3 of the history processing pipeline.
pub fn reveal_votes(agg: &mut RemarkAggregation) {
    for (context, config) in agg.context_configs.iter() {
        if config.common_salts.is_empty() {
            continue;
        }

        let Some(commits) = agg.context_commits.get(context) else {
            continue;
        };

        let Some(revealed_salts) = agg.context_revealed_salts.get(context) else {
            continue;
        };

        let Some(votes) = agg.context_votes.get_mut(context) else {
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
}

/// Pure function: Build final VotingHistory from aggregation
pub fn build_voting_history(mut agg: RemarkAggregation) -> VotingHistory {
    let mut contexts = HashMap::new();
    for (context, config) in agg.context_configs {
        let votes = agg.context_votes.remove(&context).unwrap_or_default();
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

    VotingHistory {
        contexts,
        voter_pubkeys: agg.voter_pubkeys,
    }
}

/// Builder for querying voting history
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

    /// Execute the query using the default MongoDB repository
    pub async fn execute(&self) -> Result<VotingHistory> {
        let repo = MongoRemarkRepository::new(&self.config);
        self.execute_with_repo(&repo).await
    }

    /// Execute the query using a custom repository (for testing)
    pub async fn execute_with_repo(&self, repo: &dyn RemarkRepository) -> Result<VotingHistory> {
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
            known_pubkeys_from_secrets.insert(HashableAccountId(account_id), account.x25519_public);
        }

        // Phase 1: Fetch and aggregate remarks
        let remarks = repo.fetch_remarks(self.filter_context.as_ref()).await?;
        let mut agg = aggregate_remarks(remarks);

        // Phase 2: Decrypt common salts
        decrypt_common_salts(&mut agg, &known_secrets, &known_pubkeys_from_secrets);

        // Phase 3: Reveal votes
        reveal_votes(&mut agg);

        // Build final result
        Ok(build_voting_history(agg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_remark(sender: [u8; 32], context: &str, msg: CorevoMessage) -> RemarkRecord {
        RemarkRecord {
            sender: AccountId32(sender),
            remark: CorevoRemarkV1 {
                context: CorevoContext::String(context.to_string()),
                msg,
            },
        }
    }

    #[test]
    fn test_aggregate_remarks_announce_pubkey() {
        let pubkey = [1u8; 32];
        let remarks = vec![make_remark(
            [10u8; 32],
            "ctx1",
            CorevoMessage::AnnounceOwnPubKey(pubkey),
        )];

        let agg = aggregate_remarks(remarks);

        assert_eq!(agg.voter_pubkeys.len(), 1);
        let key = HashableAccountId(AccountId32([10u8; 32]));
        assert_eq!(agg.voter_pubkeys.get(&key), Some(&pubkey));
    }

    #[test]
    fn test_aggregate_remarks_invite_voter() {
        let voter = AccountId32([20u8; 32]);
        let encrypted_salt = vec![0xca, 0xfe];
        let remarks = vec![make_remark(
            [10u8; 32], // proposer
            "ctx1",
            CorevoMessage::InviteVoter(voter.clone(), encrypted_salt.clone()),
        )];

        let agg = aggregate_remarks(remarks);

        let ctx = CorevoContext::String("ctx1".to_string());
        let config = agg.context_configs.get(&ctx).unwrap();
        assert_eq!(config.proposer, AccountId32([10u8; 32]));
        assert!(config.voters.contains(&HashableAccountId(voter.clone())));
        assert_eq!(
            config.encrypted_common_salts.get(&HashableAccountId(voter)),
            Some(&vec![encrypted_salt])
        );
    }

    #[test]
    fn test_aggregate_remarks_commit() {
        let commitment = [3u8; 32];
        let encrypted_vote = vec![0xbe, 0xef];
        let remarks = vec![make_remark(
            [10u8; 32],
            "ctx1",
            CorevoMessage::Commit(commitment, encrypted_vote),
        )];

        let agg = aggregate_remarks(remarks);

        let ctx = CorevoContext::String("ctx1".to_string());
        let voter = HashableAccountId(AccountId32([10u8; 32]));
        assert!(matches!(
            agg.context_votes.get(&ctx).unwrap().get(&voter),
            Some(VoteStatus::Committed(c)) if *c == commitment
        ));
    }

    #[test]
    fn test_aggregate_remarks_reveal_after_commit() {
        let commitment = [3u8; 32];
        let onetime_salt = [4u8; 32];
        let sender = [10u8; 32];
        let remarks = vec![
            make_remark(
                sender,
                "ctx1",
                CorevoMessage::Commit(commitment, vec![0xbe, 0xef]),
            ),
            make_remark(
                sender,
                "ctx1",
                CorevoMessage::RevealOneTimeSalt(onetime_salt),
            ),
        ];

        let agg = aggregate_remarks(remarks);

        let ctx = CorevoContext::String("ctx1".to_string());
        let voter = HashableAccountId(AccountId32(sender));

        // Should be marked as pending brute-force
        assert!(matches!(
            agg.context_votes.get(&ctx).unwrap().get(&voter),
            Some(VoteStatus::Revealed(Err("Pending brute-force")))
        ));

        // Salt should be recorded
        assert_eq!(
            agg.context_revealed_salts.get(&ctx).unwrap().get(&voter),
            Some(&onetime_salt)
        );
    }

    #[test]
    fn test_aggregate_remarks_reveal_without_commit() {
        let onetime_salt = [4u8; 32];
        let remarks = vec![make_remark(
            [10u8; 32],
            "ctx1",
            CorevoMessage::RevealOneTimeSalt(onetime_salt),
        )];

        let agg = aggregate_remarks(remarks);

        let ctx = CorevoContext::String("ctx1".to_string());
        let voter = HashableAccountId(AccountId32([10u8; 32]));

        assert!(matches!(
            agg.context_votes.get(&ctx).unwrap().get(&voter),
            Some(VoteStatus::RevealedWithoutCommitment)
        ));
    }

    #[test]
    fn test_reveal_votes_finds_correct_vote() {
        use crate::primitives::CorevoVoteAndSalt;

        let onetime_salt = [1u8; 32];
        let common_salt = [2u8; 32];
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Aye,
            onetime_salt,
        };
        let commitment = vote_and_salt.commit(Some(common_salt));
        let sender = [10u8; 32];
        let ctx = CorevoContext::String("ctx1".to_string());

        let mut agg = RemarkAggregation::default();

        // Set up context config with common salt
        agg.context_configs.insert(
            ctx.clone(),
            ContextConfig {
                proposer: AccountId32(sender),
                voters: HashSet::new(),
                common_salts: vec![common_salt],
                encrypted_common_salts: HashMap::new(),
            },
        );

        // Set up commit
        let voter = HashableAccountId(AccountId32(sender));
        let mut commits = HashMap::new();
        commits.insert(
            voter.clone(),
            CommitData {
                commitment,
                encrypted_vote_and_salt: vec![],
            },
        );
        agg.context_commits.insert(ctx.clone(), commits);

        // Set up revealed salt
        let mut revealed = HashMap::new();
        revealed.insert(voter.clone(), onetime_salt);
        agg.context_revealed_salts.insert(ctx.clone(), revealed);

        // Set up pending vote status
        let mut votes = HashMap::new();
        votes.insert(
            voter.clone(),
            VoteStatus::Revealed(Err("Pending brute-force")),
        );
        agg.context_votes.insert(ctx.clone(), votes);

        // Run revelation
        reveal_votes(&mut agg);

        // Check result
        let vote_status = agg.context_votes.get(&ctx).unwrap().get(&voter);
        assert!(matches!(
            vote_status,
            Some(VoteStatus::Revealed(Ok(CorevoVote::Aye)))
        ));
    }

    #[test]
    fn test_build_voting_history() {
        let ctx = CorevoContext::String("test".to_string());
        let proposer = AccountId32([1u8; 32]);
        let voter = HashableAccountId(AccountId32([2u8; 32]));
        let pubkey = [3u8; 32];

        let mut agg = RemarkAggregation::default();
        agg.voter_pubkeys.insert(voter.clone(), pubkey);
        agg.context_configs.insert(
            ctx.clone(),
            ContextConfig {
                proposer: proposer.clone(),
                voters: {
                    let mut s = HashSet::new();
                    s.insert(voter.clone());
                    s
                },
                common_salts: vec![[4u8; 32]],
                encrypted_common_salts: HashMap::new(),
            },
        );
        agg.context_votes.insert(ctx.clone(), {
            let mut m = HashMap::new();
            m.insert(voter.clone(), VoteStatus::Revealed(Ok(CorevoVote::Nay)));
            m
        });

        let history = build_voting_history(agg);

        assert_eq!(history.contexts.len(), 1);
        let summary = history.contexts.get(&ctx).unwrap();
        assert_eq!(summary.proposer, proposer);
        assert!(summary.voters.contains(&voter));
        assert!(matches!(
            summary.votes.get(&voter),
            Some(VoteStatus::Revealed(Ok(CorevoVote::Nay)))
        ));
    }

    #[test]
    fn test_hashable_account_id_hash_eq() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a1 = HashableAccountId(AccountId32([1u8; 32]));
        let a2 = HashableAccountId(AccountId32([1u8; 32]));
        let a3 = HashableAccountId(AccountId32([2u8; 32]));

        // Equality
        assert_eq!(a1, a2);
        assert_ne!(a1, a3);

        // Hash consistency
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        a1.hash(&mut h1);
        a2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

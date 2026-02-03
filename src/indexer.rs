use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use codec::Decode;
use futures::TryStreamExt;
use mongodb::{bson::{doc, Bson}, options::ClientOptions, Client};
use subxt::utils::AccountId32;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use crate::chain_helpers::decode_hex;
use crate::crypto::decrypt_from_sender;
use crate::primitives::{Commitment, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1, CorevoVote, CorevoVoteAndSalt, PrefixedCorevoRemark, PublicKeyForEncryption, Salt, VotingAccount};

#[derive(Clone, Debug)]
pub struct ContextConfig {
    pub proposer: AccountId32,
    pub voters: HashSet<HashableAccountId>,
    /// All decrypted common salts for this context (multiple invitation rounds possible)
    pub common_salts: Vec<Salt>,
    /// All encrypted common salts for each voter (from InviteVoter messages) - multiple per voter possible
    pub encrypted_common_salts: HashMap<HashableAccountId, Vec<Vec<u8>>>,
}

/// Holds commit data for later verification
#[derive(Clone, Debug)]
pub struct CommitData {
    pub commitment: Commitment,
    pub encrypted_vote_and_salt: Vec<u8>,
}

/// Holds the last known status of one participant's vote, whether we can decipher it or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteStatus {
    Committed(Commitment),
    Revealed(Result<CorevoVote, &'static str>),
    RevealedWithoutCommitment
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashableAccountId(AccountId32);

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


/// Get voting history and reveal votes using known voting accounts
///
/// # Arguments
/// * `known_accounts` - List of VotingAccount references with pre-derived X25519 keys
pub async fn get_history(known_accounts: &[&VotingAccount]) -> Result<(), Box<dyn std::error::Error>> {
    // Build lookup maps from provided accounts
    let mut known_secrets: HashMap<HashableAccountId, StaticSecret> = HashMap::new();
    let mut known_pubkeys_from_secrets: HashMap<HashableAccountId, X25519PublicKey> = HashMap::new();

    println!("🔑 Using {} known accounts for decryption...", known_accounts.len());
    for account in known_accounts {
        let account_id = account.sr25519_keypair.public_key().to_account_id();
        println!("🔑   {}", account_id);
        known_secrets.insert(HashableAccountId(account_id.clone()), account.x25519_secret.clone());
        known_pubkeys_from_secrets.insert(HashableAccountId(account_id), account.x25519_public);
    }

    let mut voter_pubkeys: HashMap<HashableAccountId, PublicKeyForEncryption> = HashMap::new();
    let mut context_configs: HashMap<CorevoContext, ContextConfig> = HashMap::new();
    let mut context_votes: HashMap<CorevoContext, HashMap<HashableAccountId, VoteStatus>> = HashMap::new();
    // Store commit data for later vote revelation
    let mut context_commits: HashMap<CorevoContext, HashMap<HashableAccountId, CommitData>> = HashMap::new();
    // Store revealed one-time salts
    let mut context_revealed_salts: HashMap<CorevoContext, HashMap<HashableAccountId, Salt>> = HashMap::new();

    // Adjust the URI, database, and collection as needed.
    let uri = "mongodb://readonly:123456@62.84.182.186:27017/?directConnection=true";
    let db_name = "litescan_kusama_assethub";
    let coll_name = "extrinsics";

    let mut client_options = ClientOptions::parse(uri).await?;
    client_options.app_name = Some("corevo-print-remarks".to_string());
    let client = Client::with_options(client_options)?;

    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>(coll_name);

    // Query: { method: "remark", "args.remark": { $regex: /^0xcc00ee/i } }
    let filter = doc! {
        "method": "remark",
        "args.remark": { "$regex": "^0xcc00ee", "$options": "i" }
    };
    let count = coll.count_documents(filter.clone()).await?;
    println!("⛓🗄️ Found {} corevo-prefixed remarks", count);

    let mut cursor = coll.find(filter).await?;
    while let Some(doc) = cursor.try_next().await? {
        // Safely navigate to args.remark
        let remark = doc.get_document("args")
            .ok()
            .and_then(|args| args.get("remark"))
            .and_then(|v| match v {
                Bson::String(s) => Some(s.as_str()),
                _ => None,
            });
        let Some(sender) = doc.get_document("signer")
            .ok()
            .and_then(|signer_doc| signer_doc.get_str("Id").ok())
            .and_then(|s| AccountId32::from_str(s).ok())
        else {
            log::warn!("ignoring remark with no signer");
            continue;
        };

        if let Some(r) = remark {
            let result = decode_hex(r)
                .and_then(|remark_bytes| Ok(PrefixedCorevoRemark::decode(&mut remark_bytes.as_slice())
                    .and_then(|pcr| {
                        #[allow(irrefutable_let_patterns)]
                        if let CorevoRemark::V1(cr) = pcr.0 {
                            log::debug!("corevo remark: {}", cr);
                            let CorevoRemarkV1 { context, msg }  = cr;
                            match msg {
                                CorevoMessage::AnnounceOwnPubKey(pubkey) => {
                                    let _ = voter_pubkeys.insert(sender.clone().into(), pubkey);
                                },
                                CorevoMessage::InviteVoter(voter, encrypted_common_salt) => {
                                    let config = context_configs.entry(context.clone())
                                        .or_insert_with(|| ContextConfig {
                                            proposer: sender.clone(),
                                            voters: HashSet::new(),
                                            common_salts: Vec::new(),
                                            encrypted_common_salts: HashMap::new(),
                                        });
                                    config.voters.insert(HashableAccountId(voter.clone()));
                                    // Store ALL encrypted salts per voter (multiple invitation rounds possible)
                                    config.encrypted_common_salts
                                        .entry(HashableAccountId(voter.clone()))
                                        .or_insert_with(Vec::new)
                                        .push(encrypted_common_salt);
                                },
                                CorevoMessage::Commit(commitment, encrypted_vote_and_salt) => {
                                    context_votes.entry(context.clone())
                                            .or_insert_with(HashMap::new)
                                            .insert(HashableAccountId(sender.clone()), VoteStatus::Committed(commitment));
                                    context_commits.entry(context.clone())
                                            .or_insert_with(HashMap::new)
                                            .insert(HashableAccountId(sender.clone()), CommitData {
                                                commitment,
                                                encrypted_vote_and_salt,
                                            });
                                },
                                CorevoMessage::RevealOneTimeSalt(onetime_salt) => {
                                    // Store the revealed salt
                                    context_revealed_salts.entry(context.clone())
                                        .or_insert_with(HashMap::new)
                                        .insert(HashableAccountId(sender.clone()), onetime_salt);

                                    let votes = context_votes.entry(context.clone())
                                        .or_insert_with(HashMap::new);
                                    match votes.get(&HashableAccountId(sender.clone())) {
                                        Some(VoteStatus::Committed(_)) => {
                                            // Mark as revealed, actual vote will be determined later
                                            votes.insert(HashableAccountId(sender.clone()), VoteStatus::Revealed(Err("Pending brute-force")));
                                        },
                                        None => {
                                            log::warn!("Vote for {} in context {:?} was revealed but we don't know of any commitment", sender, context);
                                            votes.insert(HashableAccountId(sender.clone()), VoteStatus::RevealedWithoutCommitment);
                                        },
                                        Some(VoteStatus::Revealed(_)) | Some(VoteStatus::RevealedWithoutCommitment) => {
                                            log::warn!("Vote for {} in context {:?} was already revealed. ignoring subsequent commitments or reveals", sender, context);
                                        },
                                    }
                                },
                            }
                        }
                        Ok(())
                    })));
            if result == Ok(Ok(())) {
                continue;
            };
            log::warn!("failed on remark: {:?}", result);
        }
    }

    // Phase 2: Try to decrypt ALL common salts using proposer secrets
    println!("🔓 ======== DECRYPTING COMMON SALTS ========");
    for (context, config) in context_configs.iter_mut() {
        println!("🔓 Context: {}", context);
        println!("🔓   Proposer: {}", config.proposer);

        // Check if we have the proposer's secret
        let proposer_key = HashableAccountId(config.proposer.clone());
        if let Some(proposer_secret) = known_secrets.get(&proposer_key) {
            // Try to decrypt ALL common salts from all invitations
            let mut seen_salts: HashSet<[u8; 32]> = HashSet::new();
            for (voter, encrypted_salts) in config.encrypted_common_salts.iter() {
                // We need the voter's X25519 public key (either from chain or from our known keys)
                let voter_pubkey = voter_pubkeys.get(voter)
                    .map(|pk| X25519PublicKey::from(*pk))
                    .or_else(|| known_pubkeys_from_secrets.get(voter).cloned());

                if let Some(voter_pub) = voter_pubkey {
                    for encrypted_salt in encrypted_salts {
                        match decrypt_from_sender(proposer_secret, &voter_pub, encrypted_salt) {
                            Ok(decrypted) => {
                                if decrypted.len() == 32 {
                                    let mut salt = [0u8; 32];
                                    salt.copy_from_slice(&decrypted);
                                    if seen_salts.insert(salt) {
                                        config.common_salts.push(salt);
                                        println!("🔓   ✅ Decrypted common salt: 0x{}", hex::encode(salt));
                                    }
                                } else {
                                    log::warn!("Decrypted salt has wrong length: {}", decrypted.len());
                                }
                            }
                            Err(e) => {
                                log::debug!("Failed to decrypt common salt for voter {}: {:?}", voter.0, e);
                            }
                        }
                    }
                }
            }

            if config.common_salts.is_empty() {
                println!("🔓   ❌ Could not decrypt any common salts (missing voter public keys?)");
            } else {
                println!("🔓   Found {} unique common salt(s)", config.common_salts.len());
            }
        } else {
            println!("🔓   ❌ No secret available for proposer");
        }
    }

    // Phase 3: Reveal votes by brute-forcing all vote options against commitments
    println!("🗳️ ======== REVEALING VOTES BY BRUTE-FORCE ========");
    for (context, config) in context_configs.iter() {
        println!("🗳️ Context: {}", context);
        if config.common_salts.is_empty() {
            println!("🗳️   Skipping (no common salt)");
            continue;
        };

        let Some(commits) = context_commits.get(context) else {
            continue;
        };

        let Some(revealed_salts) = context_revealed_salts.get(context) else {
            continue;
        };

        let mut votes = context_votes.get_mut(context);

        for (voter, commit_data) in commits.iter() {
            if let Some(onetime_salt) = revealed_salts.get(voter) {
                // Brute-force the vote by trying all common salts and vote options
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
                    println!("🗳️   {} -> {:?}", voter.0, vote);
                    if let Some(ref mut votes_map) = votes {
                        votes_map.insert(voter.clone(), VoteStatus::Revealed(Ok(vote)));
                    }
                } else {
                    println!("🗳️   {} -> ❌ No vote option matched commitment", voter.0);
                    if let Some(ref mut votes_map) = votes {
                        votes_map.insert(voter.clone(), VoteStatus::Revealed(Err("No vote matched commitment")));
                    }
                }
            }
        }
    }
    println!("⛓🗄️ ======== TURNOUT FOR ALL CONTEXTS ========");
    for (context, config) in context_configs.iter() {
        println!("⛓🗄️ Context: {}", context);
        println!("⛓🗄️   Proposer: {}", config.proposer);
        println!("⛓🗄️   Invited Voters:");
        for voter in config.voters.iter() {
            println!("⛓🗄️     {}", voter.0);
        }
        if let Some(votes) = context_votes.get(context) {
            println!("⛓🗄️   Votes:");
            for voter in config.voters.iter() {
                match votes.get(voter) {
                    None => {
                        println!("⛓🗄️     {}: Uncast", voter.0);
                    },
                    Some(VoteStatus::Committed(_)) => {
                        println!("⛓🗄️     {}: Committed (not revealed yet)", voter.0);
                    },
                    Some(VoteStatus::Revealed(Ok(vote))) => {
                        println!("⛓🗄️     {}: Revealed vote {:?}", voter.0, vote);
                    },
                    Some(VoteStatus::Revealed(Err(e))) => {
                        println!("⛓🗄️     {}: Revealed but could not decipher vote: {}", voter.0, e);
                    },
                    Some(VoteStatus::RevealedWithoutCommitment) => {
                        println!("⛓🗄️     {}: Revealed without prior commitment", voter.0);
                    },
                }
            }
        } else {
            println!("⛓🗄️   No votes recorded for this context.");
        }
    }
    println!("⛓🗄️ ========");
    Ok(())
}
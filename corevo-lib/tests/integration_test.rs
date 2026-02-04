//! Integration tests for the full CoReVo voting flow.
//!
//! These tests use mock implementations of ChainApi and RemarkRepository
//! to verify the complete voting workflow without requiring actual chain
//! or database connections.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use codec::Encode;
use corevo_lib::{
    AccountId32, CorevoContext, CorevoMessage, CorevoRemarkV1, CorevoVote, CorevoVoteAndSalt,
    HashableAccountId, RemarkRecord, RemarkRepository, Result, VoteStatus, VotingAccount,
    aggregate_remarks, build_voting_history, decrypt_common_salts, derive_account_from_uri,
    encrypt_for_recipient, reveal_votes,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Mock chain that stores all sent remarks in memory
#[derive(Clone, Default)]
struct MockChain {
    /// All remarks sent, with sender and block number
    remarks: Arc<Mutex<Vec<(AccountId32, CorevoRemarkV1, u64)>>>,
    /// Current block number
    block_number: Arc<Mutex<u64>>,
}

impl MockChain {
    fn new() -> Self {
        Self::default()
    }

    /// Send a remark to the mock chain
    fn send_remark(&self, sender: &AccountId32, remark: CorevoRemarkV1) {
        let mut remarks = self.remarks.lock().unwrap();
        let mut block = self.block_number.lock().unwrap();
        *block += 1;
        remarks.push((sender.clone(), remark, *block));
    }

    /// Get all remarks as RemarkRecords
    fn get_remarks(&self) -> Vec<RemarkRecord> {
        let remarks = self.remarks.lock().unwrap();
        remarks
            .iter()
            .map(|(sender, remark, _block)| RemarkRecord {
                sender: sender.clone(),
                remark: remark.clone(),
            })
            .collect()
    }
}

/// Mock repository that returns remarks from the MockChain
struct MockRemarkRepository {
    chain: MockChain,
}

impl MockRemarkRepository {
    fn new(chain: MockChain) -> Self {
        Self { chain }
    }
}

#[async_trait]
impl RemarkRepository for MockRemarkRepository {
    async fn fetch_remarks(
        &self,
        filter_context: Option<&CorevoContext>,
    ) -> Result<Vec<RemarkRecord>> {
        let all_remarks = self.chain.get_remarks();
        if let Some(ctx) = filter_context {
            Ok(all_remarks
                .into_iter()
                .filter(|r| &r.remark.context == ctx)
                .collect())
        } else {
            Ok(all_remarks)
        }
    }
}

/// Helper to create a remark and send it to the mock chain
fn send_remark(
    chain: &MockChain,
    account: &VotingAccount,
    context: &CorevoContext,
    msg: CorevoMessage,
) {
    let sender = account.sr25519_keypair.public_key().to_account_id();
    let remark = CorevoRemarkV1 {
        context: context.clone(),
        msg,
    };
    chain.send_remark(&sender, remark);
}

/// Full voting flow integration test
///
/// Scenario:
/// - Alice (proposer) and Bob (voter) participate
/// - Alice announces her pubkey
/// - Bob announces his pubkey
/// - Alice proposes a context and invites both Alice and Bob
/// - Alice commits Aye
/// - Bob commits Nay
/// - Alice reveals
/// - Bob reveals
/// - Verify final history shows correct votes
#[tokio::test]
async fn test_full_voting_flow_with_common_salt() {
    // Setup accounts
    let alice = derive_account_from_uri("//Alice").unwrap();
    let bob = derive_account_from_uri("//Bob").unwrap();

    let alice_account_id = alice.sr25519_keypair.public_key().to_account_id();
    let bob_account_id = bob.sr25519_keypair.public_key().to_account_id();

    // Setup mock chain
    let chain = MockChain::new();
    let context = CorevoContext::String("test-proposal-2024".to_string());

    // Phase 1: Announce pubkeys
    // Both Alice and Bob announce their X25519 public keys
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::AnnounceOwnPubKey(alice.x25519_public.to_bytes()),
    );
    send_remark(
        &chain,
        &bob,
        &context,
        CorevoMessage::AnnounceOwnPubKey(bob.x25519_public.to_bytes()),
    );

    // Phase 2: Propose & Invite
    // Alice (proposer) generates a common salt and invites both voters
    let common_salt: [u8; 32] = [42u8; 32]; // In real code, use random

    // Encrypt common salt for Alice (self)
    let encrypted_salt_alice =
        encrypt_for_recipient(&alice.x25519_secret, &alice.x25519_public, &common_salt).unwrap();
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::InviteVoter(alice_account_id.clone(), encrypted_salt_alice),
    );

    // Encrypt common salt for Bob
    let encrypted_salt_bob =
        encrypt_for_recipient(&alice.x25519_secret, &bob.x25519_public, &common_salt).unwrap();
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::InviteVoter(bob_account_id.clone(), encrypted_salt_bob),
    );

    // Phase 3: Commit votes
    // Alice commits Aye
    let alice_onetime_salt: [u8; 32] = [1u8; 32];
    let alice_vote_and_salt = CorevoVoteAndSalt {
        vote: CorevoVote::Aye,
        onetime_salt: alice_onetime_salt,
    };
    let alice_commitment = alice_vote_and_salt.commit(Some(common_salt));

    // Encrypt vote+salt for self (persistence)
    let alice_encrypted_vote = encrypt_for_recipient(
        &alice.x25519_secret,
        &alice.x25519_public,
        &alice_vote_and_salt.encode(),
    )
    .unwrap();
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::Commit(alice_commitment, alice_encrypted_vote),
    );

    // Bob commits Nay
    let bob_onetime_salt: [u8; 32] = [2u8; 32];
    let bob_vote_and_salt = CorevoVoteAndSalt {
        vote: CorevoVote::Nay,
        onetime_salt: bob_onetime_salt,
    };
    let bob_commitment = bob_vote_and_salt.commit(Some(common_salt));

    let bob_encrypted_vote = encrypt_for_recipient(
        &bob.x25519_secret,
        &bob.x25519_public,
        &bob_vote_and_salt.encode(),
    )
    .unwrap();
    send_remark(
        &chain,
        &bob,
        &context,
        CorevoMessage::Commit(bob_commitment, bob_encrypted_vote),
    );

    // Phase 4: Reveal votes
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::RevealOneTimeSalt(alice_onetime_salt),
    );
    send_remark(
        &chain,
        &bob,
        &context,
        CorevoMessage::RevealOneTimeSalt(bob_onetime_salt),
    );

    // Phase 5: Fetch history and verify
    let repo = MockRemarkRepository::new(chain);
    let remarks = repo.fetch_remarks(None).await.unwrap();

    // Process remarks through the indexer pipeline
    let mut agg = aggregate_remarks(remarks);

    // Build secrets map for decryption (using Alice as proposer)
    let mut known_secrets: HashMap<HashableAccountId, StaticSecret> = HashMap::new();
    let mut known_pubkeys: HashMap<HashableAccountId, X25519PublicKey> = HashMap::new();

    known_secrets.insert(
        HashableAccountId::from(alice_account_id.clone()),
        alice.x25519_secret.clone(),
    );
    known_pubkeys.insert(
        HashableAccountId::from(alice_account_id.clone()),
        alice.x25519_public,
    );
    known_secrets.insert(
        HashableAccountId::from(bob_account_id.clone()),
        bob.x25519_secret.clone(),
    );
    known_pubkeys.insert(
        HashableAccountId::from(bob_account_id.clone()),
        bob.x25519_public,
    );

    // Decrypt common salts
    decrypt_common_salts(&mut agg, &known_secrets, &known_pubkeys);

    // Reveal votes via brute-force
    reveal_votes(&mut agg);

    // Build final history
    let history = build_voting_history(agg);

    // Verify results
    assert_eq!(history.contexts.len(), 1, "Should have exactly one context");

    let summary = history
        .contexts
        .get(&context)
        .expect("Context should exist");
    assert_eq!(
        summary.proposer, alice_account_id,
        "Alice should be proposer"
    );
    assert_eq!(summary.voters.len(), 2, "Should have 2 voters");
    assert!(
        summary
            .voters
            .contains(&HashableAccountId::from(alice_account_id.clone())),
        "Alice should be a voter"
    );
    assert!(
        summary
            .voters
            .contains(&HashableAccountId::from(bob_account_id.clone())),
        "Bob should be a voter"
    );

    // Verify Alice's vote is Aye
    let alice_vote = summary
        .votes
        .get(&HashableAccountId::from(alice_account_id.clone()))
        .expect("Alice should have a vote");
    assert!(
        matches!(alice_vote, VoteStatus::Revealed(Ok(CorevoVote::Aye))),
        "Alice's vote should be Aye, got {:?}",
        alice_vote
    );

    // Verify Bob's vote is Nay
    let bob_vote = summary
        .votes
        .get(&HashableAccountId::from(bob_account_id.clone()))
        .expect("Bob should have a vote");
    assert!(
        matches!(bob_vote, VoteStatus::Revealed(Ok(CorevoVote::Nay))),
        "Bob's vote should be Nay, got {:?}",
        bob_vote
    );

    // Verify pubkeys were recorded
    assert!(
        history
            .voter_pubkeys
            .contains_key(&HashableAccountId::from(alice_account_id)),
        "Alice's pubkey should be recorded"
    );
    assert!(
        history
            .voter_pubkeys
            .contains_key(&HashableAccountId::from(bob_account_id)),
        "Bob's pubkey should be recorded"
    );
}

/// Test voting flow without common salt (public proposal)
#[tokio::test]
async fn test_voting_flow_public_proposal() {
    // Setup accounts
    let alice = derive_account_from_uri("//Alice").unwrap();
    let bob = derive_account_from_uri("//Bob").unwrap();

    let alice_account_id = alice.sr25519_keypair.public_key().to_account_id();
    let bob_account_id = bob.sr25519_keypair.public_key().to_account_id();

    let chain = MockChain::new();
    let context = CorevoContext::String("public-proposal-2024".to_string());

    // Announce pubkeys
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::AnnounceOwnPubKey(alice.x25519_public.to_bytes()),
    );
    send_remark(
        &chain,
        &bob,
        &context,
        CorevoMessage::AnnounceOwnPubKey(bob.x25519_public.to_bytes()),
    );

    // Invite without common salt (empty encrypted_salt)
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::InviteVoter(alice_account_id.clone(), vec![]),
    );
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::InviteVoter(bob_account_id.clone(), vec![]),
    );

    // Commit without common salt
    let alice_onetime_salt: [u8; 32] = [11u8; 32];
    let alice_vote_and_salt = CorevoVoteAndSalt {
        vote: CorevoVote::Abstain,
        onetime_salt: alice_onetime_salt,
    };
    let alice_commitment = alice_vote_and_salt.commit(None); // No common salt

    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::Commit(alice_commitment, vec![]), // No encrypted vote needed
    );

    let bob_onetime_salt: [u8; 32] = [22u8; 32];
    let bob_vote_and_salt = CorevoVoteAndSalt {
        vote: CorevoVote::Aye,
        onetime_salt: bob_onetime_salt,
    };
    let bob_commitment = bob_vote_and_salt.commit(None);

    send_remark(
        &chain,
        &bob,
        &context,
        CorevoMessage::Commit(bob_commitment, vec![]),
    );

    // Reveal
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::RevealOneTimeSalt(alice_onetime_salt),
    );
    send_remark(
        &chain,
        &bob,
        &context,
        CorevoMessage::RevealOneTimeSalt(bob_onetime_salt),
    );

    // Fetch and verify - no secrets needed for public proposal
    let repo = MockRemarkRepository::new(chain);
    let remarks = repo.fetch_remarks(None).await.unwrap();

    let mut agg = aggregate_remarks(remarks);

    // No decryption needed for public proposal
    let empty_secrets: HashMap<HashableAccountId, StaticSecret> = HashMap::new();
    let empty_pubkeys: HashMap<HashableAccountId, X25519PublicKey> = HashMap::new();
    decrypt_common_salts(&mut agg, &empty_secrets, &empty_pubkeys);

    reveal_votes(&mut agg);
    let history = build_voting_history(agg);

    // Verify
    let summary = history
        .contexts
        .get(&context)
        .expect("Context should exist");

    let alice_vote = summary
        .votes
        .get(&HashableAccountId::from(alice_account_id))
        .expect("Alice should have a vote");
    assert!(
        matches!(alice_vote, VoteStatus::Revealed(Ok(CorevoVote::Abstain))),
        "Alice's vote should be Abstain, got {:?}",
        alice_vote
    );

    let bob_vote = summary
        .votes
        .get(&HashableAccountId::from(bob_account_id))
        .expect("Bob should have a vote");
    assert!(
        matches!(bob_vote, VoteStatus::Revealed(Ok(CorevoVote::Aye))),
        "Bob's vote should be Aye, got {:?}",
        bob_vote
    );
}

/// Test that votes cannot be revealed with wrong salt
#[tokio::test]
async fn test_vote_reveal_fails_with_wrong_commitment() {
    let alice = derive_account_from_uri("//Alice").unwrap();
    let alice_account_id = alice.sr25519_keypair.public_key().to_account_id();

    let chain = MockChain::new();
    let context = CorevoContext::String("wrong-salt-test".to_string());

    // Announce
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::AnnounceOwnPubKey(alice.x25519_public.to_bytes()),
    );

    // Invite (public)
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::InviteVoter(alice_account_id.clone(), vec![]),
    );

    // Commit with one salt
    let real_salt: [u8; 32] = [1u8; 32];
    let vote_and_salt = CorevoVoteAndSalt {
        vote: CorevoVote::Aye,
        onetime_salt: real_salt,
    };
    let commitment = vote_and_salt.commit(None);

    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::Commit(commitment, vec![]),
    );

    // Reveal with WRONG salt
    let wrong_salt: [u8; 32] = [99u8; 32];
    send_remark(
        &chain,
        &alice,
        &context,
        CorevoMessage::RevealOneTimeSalt(wrong_salt),
    );

    // Process
    let repo = MockRemarkRepository::new(chain);
    let remarks = repo.fetch_remarks(None).await.unwrap();

    let mut agg = aggregate_remarks(remarks);
    let empty: HashMap<HashableAccountId, StaticSecret> = HashMap::new();
    let empty_pk: HashMap<HashableAccountId, X25519PublicKey> = HashMap::new();
    decrypt_common_salts(&mut agg, &empty, &empty_pk);
    reveal_votes(&mut agg);

    let history = build_voting_history(agg);
    let summary = history.contexts.get(&context).unwrap();

    // Vote should NOT be successfully revealed
    let alice_vote = summary
        .votes
        .get(&HashableAccountId::from(alice_account_id))
        .expect("Alice should have a vote entry");

    assert!(
        matches!(alice_vote, VoteStatus::Revealed(Err(_))),
        "Vote should fail to reveal with wrong salt, got {:?}",
        alice_vote
    );
}

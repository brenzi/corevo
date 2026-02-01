use std::collections::HashMap;
use std::str::FromStr;
use subxt::{
    OnlineClient, PolkadotConfig,
    utils::{AccountId32, MultiAddress},
};
use subxt_signer::{ExposeSecret, SecretUri};
use subxt_signer::sr25519::Keypair;
use rand::{random};
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, ChaChaBox, aead::{Aead, AeadCore, OsRng}};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use codec::{Decode, Encode, Output, Input};
use futures::future::join_all;
use blake2::{Blake2b512, Digest};

#[subxt::subxt(runtime_metadata_path = "paseo_people_metadata.scale")]
pub mod assethub {}

// PolkadotConfig or SubstrateConfig will suffice for this example at the moment,
// but PolkadotConfig is a little more correct, having the right `Address` type.
type AssetHubConfig = PolkadotConfig;

/// we prefix our remarks with a unique byte sequence to identify them easily.
const COREVO_REMARK_PREFIX: [u8; 3] = hex_literal::hex!("cc00ee");
const CONTEXT: &str = "corevo_test_voting";

struct VotingAccount {
    pub sr25519_keypair: Keypair,
    pub x25519_public: X25519PublicKey,
    pub x25519_secret: StaticSecret,
}

// ensure backwards compatibility if we can migrate our message formats in the future
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
enum CorevoRemark {
    V1(CorevoRemarkV1)
}

/// for easy filtering, we prefix the encoded remark
#[derive(Debug, PartialEq, Eq, Clone)]
struct PrefixedCorevoRemark(CorevoRemark);
impl Encode for PrefixedCorevoRemark {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&COREVO_REMARK_PREFIX);
        self.0.encode_to(dest);
    }

    fn size_hint(&self) -> usize {
        COREVO_REMARK_PREFIX.len() + self.0.size_hint()
    }
}

impl Decode for PrefixedCorevoRemark {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut prefix = [0u8; 3];
        input.read(&mut prefix)?;
        if prefix != COREVO_REMARK_PREFIX {
            return Err("invalid Corevo remark prefix".into());
        }
        let cr = CorevoRemark::decode(input)?;
        Ok(PrefixedCorevoRemark(cr))
    }
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
struct CorevoRemarkV1 {
    pub context: Vec<u8>,
    pub msg: CorevoMessage
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
enum CorevoMessage {
    /// tell the world your X25519 pubkey so anyone can send you encrypted messages
    AnnounceOwnPubKey([u8; 32]),
    /// Invite a voter to participate and share an E2EE common salt for the group
    InviteVoter(AccountId32, Vec<u8>),
    /// Commit your salted vote hash and persist the [`CorevoVoteAndSalt`], encrypted to yourself
    Commit([u8; 32], Vec<u8>),
    /// Reveal your indovidual salted for the vote you committed to
    RevealOneTimeSalt([u8; 32]),
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
struct CorevoVoteAndSalt {
    pub vote: CorevoVote,
    pub onetime_salt: [u8; 32]
}

impl CorevoVoteAndSalt {
    pub fn hash(&self, maybe_common_salt: Option<[u8; 32]>) -> [u8; 32] {
        let mut hasher = Blake2b512::new();
        hasher.update(self.onetime_salt);
        if let Some(common_salt) = maybe_common_salt {
            hasher.update(common_salt);
        }
        let hash = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash[..32]);
        hash_bytes
    }
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone, Copy)]
enum CorevoVote {
    Aye,
    Nay,
    Abstain,
}

#[tokio::main]
pub async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let api = OnlineClient::<AssetHubConfig>::from_url("wss://sys.ibp.network/people-paseo").await?;
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
    println!("⛓ Listening to System.Remark Extrinsics in new finalized blocks...");

    println!("*********** SETUP PHASE **************" );
    // Every voter publishes their X25519 public key on-chain using System.Remark
    let _ = join_all(everybody.iter().map(|signer|
        send_remark(&api, &signer.sr25519_keypair,
                    CorevoRemark::V1(CorevoRemarkV1 {
                        context: CONTEXT.as_bytes().to_vec(),
                        msg: CorevoMessage::AnnounceOwnPubKey(signer.x25519_public.to_bytes())
                    })))).await;
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
            context: CONTEXT.as_bytes().to_vec(),
            msg: CorevoMessage::InviteVoter(
                account.sr25519_keypair.public_key().to_account_id(),
                encrypt_for_recipient(&proposer.x25519_secret, &account.x25519_public, &common_salt.into()).unwrap()
            )
        })).await?
    }

    println!("*********** COMMIT PHASE ************" );
    let mut everybody_votes = HashMap::<[u8; 32], CorevoVoteAndSalt>::new();
    // Every voter publishes their commitment
    let _ = join_all(everybody.clone().iter().map(|signer| {
        let vote = CorevoVote::Aye;
        let onetime_salt = random::<[u8; 32]>();
        let vote_and_salt = CorevoVoteAndSalt { vote, onetime_salt };
        everybody_votes.insert(signer.sr25519_keypair.public_key().0, vote_and_salt.clone());
        let commitment = vote_and_salt.hash(Some(common_salt));
        println!("🗳 Voter {} commits to vote {:?} with onetime_salt 0x{} resulting in commitment 0x{}",
            signer.sr25519_keypair.public_key().to_account_id(),
            vote,
            hex::encode(onetime_salt.encode()),
            hex::encode(commitment.encode())
        );
        send_remark(&api, &signer.sr25519_keypair,
                    CorevoRemark::V1(CorevoRemarkV1 {
                        context: CONTEXT.as_bytes().to_vec(),
                        msg: CorevoMessage::Commit(commitment,
                        encrypt_for_recipient(&signer.x25519_secret, &signer.x25519_public,
                            &vote_and_salt.encode()).unwrap_or_default())
                    }))
    })).await;

    println!("*********** REVEAL PHASE ************" );
    // Every voter reveals their vote
    let _ = join_all(everybody.clone().iter().map(|signer| {
        let vote_and_salt = everybody_votes.get(&signer.sr25519_keypair.public_key().0).unwrap();
        send_remark(&api, &signer.sr25519_keypair,
                    CorevoRemark::V1(CorevoRemarkV1 {
                        context: CONTEXT.as_bytes().to_vec(),
                        msg: CorevoMessage::RevealOneTimeSalt(vote_and_salt.onetime_salt)
                    }))
    })).await;

    listener_handle.await?;
    Ok(())
}


async fn derive_account(api: &OnlineClient<AssetHubConfig>, secret: &str) -> Result<VotingAccount, Box<dyn std::error::Error>> {
    let uri = SecretUri::from_str(secret)?;
    let sr25519_keypair = Keypair::from_uri(&uri)?;

    // derive X25519 keypair
    let mut hasher = Blake2b512::new();
    hasher.update(uri.phrase.expose_secret().as_bytes());
    if let Some(password) = &uri.password {
        hasher.update(password.expose_secret().as_bytes());
    }
    // Add junctions for derivation path
    for junction in &uri.junctions {
        hasher.update(format!("{:?}", junction).as_bytes());
    }
    let hash = hasher.finalize();

    let x25519_secret = StaticSecret::from(<[u8; 32]>::try_from(&hash[..32]).unwrap());
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // check account on chain
    let account_id = sr25519_keypair.public_key().to_account_id();
    println!("Address for {}: {}", secret, account_id);
    let storage = api.storage().at_latest().await?;
    let account_info = storage
        .fetch(&assethub::storage().system().account(account_id))
        .await?.expect("Account should exist");
    println!("   {} has balance of {:?}", secret, account_info.data.free);
    Ok(VotingAccount { sr25519_keypair, x25519_public, x25519_secret })
}

async fn listen_to_blocks(api: OnlineClient<AssetHubConfig>) -> Result<(), Box<dyn std::error::Error>> {
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
                if let Ok(corevo_remark) = CorevoRemark::decode(&mut remark.remark.as_slice()) {
                    match corevo_remark {
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

async fn send_remark(api: &OnlineClient<AssetHubConfig>, signer: &Keypair, remark: CorevoRemark) -> Result<(), Box<dyn std::error::Error>> {
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

/// Encrypt 32 bytes for a recipient using their X25519 public key
pub fn encrypt_for_recipient(
    sender_x25519_secret: &StaticSecret,
    recipient_x25519_public: &X25519PublicKey,
    plaintext: &Vec<u8>,
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let their_box_public = BoxPublicKey::from(*recipient_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(sender_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = crypto_box.encrypt(&nonce, plaintext.as_ref())?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt message from sender using their X25519 public key
pub fn decrypt_from_sender(
    recipient_x25519_secret: &StaticSecret,
    sender_x25519_public: &X25519PublicKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    // Extract nonce (first 24 bytes) and ciphertext (rest)
    if ciphertext.len() < 24 {
        return Err(crypto_box::aead::Error);
    }

    let (nonce_bytes, encrypted_data) = ciphertext.split_at(24);
    let nonce = crypto_box::Nonce::from_slice(nonce_bytes);

    // Create crypto_box from recipient secret and sender public
    let their_box_public = BoxPublicKey::from(*sender_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(recipient_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    // Decrypt
    let plaintext = crypto_box.decrypt(nonce, encrypted_data)?;
    Ok(plaintext)
}

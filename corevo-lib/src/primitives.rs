use std::fmt::Display;

use blake2::{Blake2b512, Digest};
use codec::{Decode, Encode, Input, Output};
use subxt::utils::AccountId32;
use subxt_signer::sr25519::Keypair;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Prefix for all CoReVo remarks on-chain (0xcc00ee)
pub const COREVO_REMARK_PREFIX: [u8; 3] = hex_literal::hex!("cc00ee");

/// Voting account with both SR25519 (signing) and X25519 (encryption) keypairs
pub struct VotingAccount {
    pub sr25519_keypair: Keypair,
    pub x25519_public: X25519PublicKey,
    pub x25519_secret: StaticSecret,
}

/// 32-byte salt used in commitment scheme
pub type Salt = [u8; 32];

/// 32-byte commitment hash
pub type Commitment = [u8; 32];

/// 32-byte X25519 public key for encryption
pub type PublicKeyForEncryption = [u8; 32];

/// Versioned envelope for CoReVo remarks - allows future protocol upgrades
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum CorevoRemark {
    V1(CorevoRemarkV1),
}

/// Prefixed remark for easy on-chain filtering via litescan/MongoDB
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrefixedCorevoRemark(pub CorevoRemark);

impl Encode for PrefixedCorevoRemark {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&COREVO_REMARK_PREFIX);
        self.0.encode_to(dest);
    }

    fn size_hint(&self) -> usize {
        COREVO_REMARK_PREFIX.len() + self.0.size_hint()
    }
}

impl From<CorevoRemark> for PrefixedCorevoRemark {
    fn from(cr: CorevoRemark) -> Self {
        PrefixedCorevoRemark(cr)
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

/// Voting context identifier - can be arbitrary bytes or human-readable string
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone, Hash)]
pub enum CorevoContext {
    Bytes(Vec<u8>),
    String(String),
}

impl Display for CorevoContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CorevoContext::Bytes(bytes) => {
                write!(f, "{}", hex_encode(bytes))
            }
            CorevoContext::String(s) => {
                write!(f, "{}", s)
            }
        }
    }
}

/// V1 remark structure with context and message
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct CorevoRemarkV1 {
    pub context: CorevoContext,
    pub msg: CorevoMessage,
}

impl Display for CorevoRemarkV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CorevoRemarkV1(context: {}, msg: {})",
            self.context, self.msg
        )
    }
}

/// Message types for different voting phases
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum CorevoMessage {
    /// Announce X25519 public key for encrypted communication
    AnnounceOwnPubKey(PublicKeyForEncryption),
    /// Invite a voter by sending them an encrypted common salt
    InviteVoter(AccountId32, Vec<u8>),
    /// Commit a salted vote hash + self-encrypted vote for persistence
    Commit(Commitment, Vec<u8>),
    /// Reveal the one-time salt to verify the vote
    RevealOneTimeSalt(Salt),
}

impl Display for CorevoMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CorevoMessage::AnnounceOwnPubKey(pubkey_bytes) => {
                write!(f, "AnnounceOwnPubKey(x25519pub: {})", hex_encode(pubkey_bytes))
            }
            CorevoMessage::InviteVoter(account, common_salt_encrypted) => {
                write!(
                    f,
                    "InviteVoter(account: {}, encrypted_common_salt: {})",
                    account,
                    hex_encode(common_salt_encrypted)
                )
            }
            CorevoMessage::Commit(commitment, _) => {
                write!(f, "Commit({})", hex_encode(commitment))
            }
            CorevoMessage::RevealOneTimeSalt(onetime_salt) => {
                write!(f, "RevealOneTimeSalt({})", hex_encode(onetime_salt))
            }
        }
    }
}

/// Vote with its one-time salt for commitment
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct CorevoVoteAndSalt {
    pub vote: CorevoVote,
    pub onetime_salt: Salt,
}

impl CorevoVoteAndSalt {
    /// Generate commitment hash: BLAKE2b(vote || onetime_salt || common_salt)
    pub fn commit(&self, maybe_common_salt: Option<Salt>) -> Commitment {
        let mut hasher = Blake2b512::new();
        hasher.update(self.vote.encode());
        hasher.update(self.onetime_salt);
        if let Some(common_salt) = maybe_common_salt {
            hasher.update(common_salt);
        }
        let hash = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash[..32]);
        hash_bytes
    }

    /// Brute-force reveal by trying all vote options against commitment
    pub fn reveal_vote_by_bruteforce(
        onetime_salt: Salt,
        common_salt: Salt,
        commitment: Commitment,
    ) -> Option<CorevoVote> {
        for vote in [CorevoVote::Aye, CorevoVote::Nay, CorevoVote::Abstain] {
            let candidate = CorevoVoteAndSalt { vote, onetime_salt };
            if candidate.commit(Some(common_salt)) == commitment {
                return Some(vote);
            }
        }
        None
    }
}

/// Vote options
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone, Copy)]
pub enum CorevoVote {
    Aye,
    Nay,
    Abstain,
}

impl Display for CorevoVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorevoVote::Aye => write!(f, "Aye"),
            CorevoVote::Nay => write!(f, "Nay"),
            CorevoVote::Abstain => write!(f, "Abstain"),
        }
    }
}

/// Hex encodes data with "0x" prefix
pub fn hex_encode(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

/// Decode hex string, handling optional "0x" prefix
pub fn decode_hex<T: AsRef<[u8]>>(message: T) -> Result<Vec<u8>, hex::FromHexError> {
    let message = message.as_ref();
    let message = match message {
        [b'0', b'x', hex_value @ ..] => hex_value,
        _ => message,
    };
    hex::decode(message)
}

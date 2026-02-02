use blake2::{Blake2b512, Digest};
use codec::{Decode, Encode, Input, Output};
use subxt::utils::AccountId32;
use subxt_signer::sr25519::Keypair;
use crate::COREVO_REMARK_PREFIX;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

pub struct VotingAccount {
    pub sr25519_keypair: Keypair,
    pub x25519_public: X25519PublicKey,
    pub x25519_secret: StaticSecret,
}

// ensure backwards compatibility if we can migrate our message formats in the future
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum CorevoRemark {
    V1(CorevoRemarkV1)
}

/// for easy filtering, we prefix the encoded remark
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

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct CorevoRemarkV1 {
    pub context: Vec<u8>,
    pub msg: CorevoMessage
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum CorevoMessage {
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
pub struct CorevoVoteAndSalt {
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
pub enum CorevoVote {
    Aye,
    Nay,
    Abstain,
}

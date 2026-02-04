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
                write!(
                    f,
                    "AnnounceOwnPubKey(x25519pub: {})",
                    hex_encode(pubkey_bytes)
                )
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

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};

    #[test]
    fn test_prefixed_remark_encode_decode_roundtrip() {
        let context = CorevoContext::String("test-context".to_string());
        let pubkey: PublicKeyForEncryption = [42u8; 32];
        let msg = CorevoMessage::AnnounceOwnPubKey(pubkey);
        let remark_v1 = CorevoRemarkV1 {
            context: context.clone(),
            msg: msg.clone(),
        };
        let original = PrefixedCorevoRemark(CorevoRemark::V1(remark_v1));

        let encoded = original.encode();
        let decoded = PrefixedCorevoRemark::decode(&mut encoded.as_slice()).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_prefixed_remark_has_correct_prefix() {
        let remark = PrefixedCorevoRemark(CorevoRemark::V1(CorevoRemarkV1 {
            context: CorevoContext::String("x".to_string()),
            msg: CorevoMessage::RevealOneTimeSalt([0u8; 32]),
        }));
        let encoded = remark.encode();
        assert_eq!(&encoded[..3], &COREVO_REMARK_PREFIX);
    }

    #[test]
    fn test_decode_fails_with_wrong_prefix() {
        let mut bad_data = vec![0xde, 0xad, 0xbe]; // wrong prefix
        bad_data.extend_from_slice(&[0u8; 50]); // some payload
        let result = PrefixedCorevoRemark::decode(&mut bad_data.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_deterministic() {
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Aye,
            onetime_salt: [1u8; 32],
        };
        let common_salt: Salt = [2u8; 32];

        let commitment1 = vote_and_salt.commit(Some(common_salt));
        let commitment2 = vote_and_salt.commit(Some(common_salt));

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_commitment_with_and_without_common_salt() {
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Aye,
            onetime_salt: [1u8; 32],
        };
        let common_salt: Salt = [2u8; 32];

        let with_salt = vote_and_salt.commit(Some(common_salt));
        let without_salt = vote_and_salt.commit(None);

        assert_ne!(with_salt, without_salt);
    }

    #[test]
    fn test_commitment_differs_by_vote() {
        let common_salt: Salt = [2u8; 32];
        let onetime_salt: Salt = [1u8; 32];

        let aye = CorevoVoteAndSalt {
            vote: CorevoVote::Aye,
            onetime_salt,
        }
        .commit(Some(common_salt));

        let nay = CorevoVoteAndSalt {
            vote: CorevoVote::Nay,
            onetime_salt,
        }
        .commit(Some(common_salt));

        let abstain = CorevoVoteAndSalt {
            vote: CorevoVote::Abstain,
            onetime_salt,
        }
        .commit(Some(common_salt));

        assert_ne!(aye, nay);
        assert_ne!(nay, abstain);
        assert_ne!(aye, abstain);
    }

    #[test]
    fn test_reveal_vote_by_bruteforce_aye() {
        let onetime_salt: Salt = [1u8; 32];
        let common_salt: Salt = [2u8; 32];
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Aye,
            onetime_salt,
        };
        let commitment = vote_and_salt.commit(Some(common_salt));

        let revealed =
            CorevoVoteAndSalt::reveal_vote_by_bruteforce(onetime_salt, common_salt, commitment);
        assert_eq!(revealed, Some(CorevoVote::Aye));
    }

    #[test]
    fn test_reveal_vote_by_bruteforce_nay() {
        let onetime_salt: Salt = [3u8; 32];
        let common_salt: Salt = [4u8; 32];
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Nay,
            onetime_salt,
        };
        let commitment = vote_and_salt.commit(Some(common_salt));

        let revealed =
            CorevoVoteAndSalt::reveal_vote_by_bruteforce(onetime_salt, common_salt, commitment);
        assert_eq!(revealed, Some(CorevoVote::Nay));
    }

    #[test]
    fn test_reveal_vote_by_bruteforce_abstain() {
        let onetime_salt: Salt = [5u8; 32];
        let common_salt: Salt = [6u8; 32];
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Abstain,
            onetime_salt,
        };
        let commitment = vote_and_salt.commit(Some(common_salt));

        let revealed =
            CorevoVoteAndSalt::reveal_vote_by_bruteforce(onetime_salt, common_salt, commitment);
        assert_eq!(revealed, Some(CorevoVote::Abstain));
    }

    #[test]
    fn test_reveal_vote_wrong_salt_fails() {
        let onetime_salt: Salt = [1u8; 32];
        let common_salt: Salt = [2u8; 32];
        let wrong_salt: Salt = [99u8; 32];
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Aye,
            onetime_salt,
        };
        let commitment = vote_and_salt.commit(Some(common_salt));

        // Wrong common salt
        let revealed =
            CorevoVoteAndSalt::reveal_vote_by_bruteforce(onetime_salt, wrong_salt, commitment);
        assert_eq!(revealed, None);

        // Wrong onetime salt
        let revealed =
            CorevoVoteAndSalt::reveal_vote_by_bruteforce(wrong_salt, common_salt, commitment);
        assert_eq!(revealed, None);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
        assert_eq!(hex_encode(&[]), "0x");
        assert_eq!(hex_encode(&[0x00, 0xff]), "0x00ff");
    }

    #[test]
    fn test_decode_hex_with_prefix() {
        assert_eq!(
            decode_hex("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        let empty: Vec<u8> = vec![];
        assert_eq!(decode_hex("0x").unwrap(), empty);
    }

    #[test]
    fn test_decode_hex_without_prefix() {
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        let empty: Vec<u8> = vec![];
        assert_eq!(decode_hex("").unwrap(), empty);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let encoded = hex_encode(&data);
        let decoded = decode_hex(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_corevo_context_string_encode_decode() {
        let ctx = CorevoContext::String("my voting context".to_string());
        let encoded = ctx.encode();
        let decoded = CorevoContext::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_corevo_context_bytes_encode_decode() {
        let ctx = CorevoContext::Bytes(vec![0xca, 0xfe, 0xba, 0xbe]);
        let encoded = ctx.encode();
        let decoded = CorevoContext::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_corevo_context_display_string() {
        let ctx = CorevoContext::String("hello".to_string());
        assert_eq!(format!("{}", ctx), "hello");
    }

    #[test]
    fn test_corevo_context_display_bytes() {
        let ctx = CorevoContext::Bytes(vec![0xca, 0xfe]);
        assert_eq!(format!("{}", ctx), "0xcafe");
    }

    #[test]
    fn test_corevo_vote_encode_decode() {
        for vote in [CorevoVote::Aye, CorevoVote::Nay, CorevoVote::Abstain] {
            let encoded = vote.encode();
            let decoded = CorevoVote::decode(&mut encoded.as_slice()).unwrap();
            assert_eq!(vote, decoded);
        }
    }

    #[test]
    fn test_corevo_vote_display() {
        assert_eq!(format!("{}", CorevoVote::Aye), "Aye");
        assert_eq!(format!("{}", CorevoVote::Nay), "Nay");
        assert_eq!(format!("{}", CorevoVote::Abstain), "Abstain");
    }

    #[test]
    fn test_corevo_message_variants_encode_decode() {
        use subxt::utils::AccountId32;

        let messages = vec![
            CorevoMessage::AnnounceOwnPubKey([42u8; 32]),
            CorevoMessage::InviteVoter(AccountId32([1u8; 32]), vec![0xde, 0xad]),
            CorevoMessage::Commit([3u8; 32], vec![0xbe, 0xef]),
            CorevoMessage::RevealOneTimeSalt([4u8; 32]),
        ];

        for msg in messages {
            let encoded = msg.encode();
            let decoded = CorevoMessage::decode(&mut encoded.as_slice()).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_corevo_vote_and_salt_encode_decode() {
        let vote_and_salt = CorevoVoteAndSalt {
            vote: CorevoVote::Nay,
            onetime_salt: [7u8; 32],
        };
        let encoded = vote_and_salt.encode();
        let decoded = CorevoVoteAndSalt::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(vote_and_salt, decoded);
    }

    #[test]
    fn test_prefixed_remark_from_corevo_remark() {
        let remark = CorevoRemark::V1(CorevoRemarkV1 {
            context: CorevoContext::String("ctx".to_string()),
            msg: CorevoMessage::RevealOneTimeSalt([0u8; 32]),
        });
        let prefixed: PrefixedCorevoRemark = remark.clone().into();
        assert_eq!(prefixed.0, remark);
    }
}

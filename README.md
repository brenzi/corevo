# CoReVo: Commit-Reveal-Voting for Substrate Chains

This repository contains a client cli tool for group-private commit-reveal voting in small groups. 

## Why Commit-Reveal Voting On A Public Blockchain?

In many situations it is desirable to 
* have immutability and auditability of voting behavior
* cast votes without knowing the vote of others and possibly getting influenced by them
* keep votes transparent within the group of voters but not revealing them publicly

## How It Works

CoReVo implements a commit-reveal voting scheme on Substrate-based blockchains using only `System.Remark` extrinsics.

### Initialization Phase

This is only needed once per voter.
Each voter generates a public/private X25519 keypair and shares their public key publicly.
CoReVo derives these keys from the same seed phrase as the Substrate account keypair, so you don't need to remember another secret.

Caveat: 
* Browser extensions don't support X25519 encryption, so you can't use such extensions to use CoReVo currently.

### Invite Phase

One member of the group sets up a new proposal to vote on
1. define a globally-unique context. Useful choices:
   * random
   * hash of a document describing the proposal
   * git hash of a repo containing deliberation material jointly populated previously
2. generate a new random *common salt* for the group
3. share *common salt* with all group members securely along with the *context*
   * by sending system.remark for each member of the group encrypted with their X25519 public key

### Commit Phase

Each member casts their vote by submitting a commitment
1. generate an individual *one-time salt* 
2. compute the commitment as `hash(vote || one_time_salt || common_salt)`
3. submit a system.remark with the commitment and the *context*
   * our goal is that nothing except the seed phrase must be remembered locally, therefore we attach the vote itself to the commitment, encrypted to self. 

### Reveal Phase

Each member reveals their vote by publishing their one-time salt along with the *context*.

Any member (or anyone who knows the *common salt*) can now count the group's votes by collecting all commitments and reveals for the given *context* and verifying them: 
For each member's last submitted commitment, guess the vote by trying all possible options using the *common salt* and the revealed *one-time salt*.

## Assumptions

* We assume sufficient social pressure within the group to reveal votes after committing them.
* We assume the group will respect the outcome of the vote as no onchain-enforcement is possible with CoReVo. 
* Counting votes is done client-side.
* Votes are opaque for the public - unless a group member leaks the *common salt*.
   * Group members see each member's vote only after the reveal phase. 

## Auditability

A group can decide to reveal their votes to an auditor by sharing the *common salt* along with the *context* for all their ballots. 
Knowing all account addresses of a group and the *common salt* for each proposal the auditor can reproduce everything from all onchain system.remarks.

## For Developers

Add or update metadata for different chains
```
cargo install subxt-cli
subxt metadata  --url wss://polkadot-asset-hub-rpc.polkadot.io:443 > polkadot_asset_hub_metadata.scale
subxt metadata  --url wss://sys.ibp.network/asset-hub-kusama:443 > kusama_asset_hub_metadata.scale
subxt metadata  --url wss://sys.ibp.network/asset-hub-paseo:443 > paseo_asset_hub_metadata.scale
subxt metadata  --url wss://collectives-paseo.rpc.amforc.com:443 > paseo_collectives_metadata.scale
```

### Indexing Voting History

We use [litescan](https://github.com/pifragile/litescan) indexer which feeds into a mongodb.
This allows for fine-grained filtering in our queries as we prefix each remark with `0xcc00ee` directly followed by a version byte and the *context*.

example litescan mongodb query:
`{method: "remark", "args.remark": { $regex: /^0xcc00ee/i }}`

TODO: mongodb query in cli and counting all votes.

Install mongosh
```
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc |    sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg    --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update
sudo apt install -y mongodb-mongosh
```

Query test
```
mongosh "mongodb://readonly:123456@62.84.182.186:27017/?directConnection=true"   --eval 'db.getSiblingDB("litescan_kusama_assethub").extrinsics.find({ method: "remark", "args.remark": { $regex: /^0xcc00ee/i } }).pretty()'
```
This should give you all CoReVo remarks on Kusama Asset Hub.
```json
[
  ...
  {
    _id: '12934873-2',
    isSigned: true,
    method: 'remark',
    assetId: null,
    era: { MortalEra: { period: '32', phase: '20' } },
    metadataHash: null,
    mode: '0',
    nonce: '6',
    signature: '0x64f8b1e08028415c264ef03056bb3e0958286959aca0ab068d0cb7d534c0057feead4614b2fa4d0aeae1fdda1b488404ef1e6ddc7948b669c0f50faed40b238a',
    signer: { Id: 'HpsnhKb3cTKmm58xCoR8VEzzJzpLJZTvoVzs5mShmqBXcnx' },
    tip: '0',
    success: true,
    blockNumber: 12934873,
    blockHash: '0xa2628c88bcaf662bcdd5aefd6ee43be44c235ec86019efb5b5d3f79eb64b10bc',
    timestamp: 1770021384000,
    args: {
      remark: '0xcc00ee0048636f7265766f5f746573745f766f74696e67031722543cb889b706ca9d517739b8eeec1b89fa957ac297dbf66f1c54fd074e8f'
    },
    section: 'system'
  }
]
```

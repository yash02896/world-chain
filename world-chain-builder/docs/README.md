## World Chain Builder

This document is intended to outline at a high level the lifecycle of a PBH Transaction within the `world-chain-builder` as well as the different components involved that make PBH possible within a optimistic rollup. 

### Overview

The `world-chain-builder` is a custom block builder integrated with [world-id](https://world.org/world-id) which implements _Priority Blockspace for Humans (PBH)_.  The builder defines a custom transaction envelope for PBH transactions while retaining backwards compatibility with standard [EIP 2718 transaction envelope](https://eips.ethereum.org/EIPS/eip-2718). This customn transaction envelope holds a [world-id](https://world.org/world-id) semaphore proof allowing the builder to verify _proof of personhood_ associated with the transaction. 

This custom transaction envelope enables a custom ordering policy during block construction that disjoins the fee markets between orb verified humans, and all other transactions on the network. This significantly mitigates the negative extranalities of Mev, and optimizes time to inclusion for verified humans on world-chain.

### PBH Envelope 
The PBH transaction envelope consists of an EIP 2718 RLP encoded transaction envelope concatenated with the RLP encoded `PbhPayload`

See
- [Pbh Payload](https://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/src/pbh/payload.rs#L50)
- [Pooled Transaction](https://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/src/primitives.rs#L14)

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldChainPooledTransactionsElement {
    pub inner: PooledTransactionsElement,
    pub pbh_payload: Option<PbhPayload>,
}

/// The payload of a PBH transaction
///
/// Contains the semaphore proof and relevent metadata
/// required to to verify the pbh transaction.
#[derive(Clone, Debug, RlpEncodable, RlpDecodable, PartialEq, Eq, Default)]
pub struct PbhPayload {
    /// A string containing a prefix, the date marker, and the pbh nonce
    pub external_nullifier: String,
    /// A nullifier hash used to keep track of
    /// previously used pbh transactions
    pub nullifier_hash: Field,
    /// The root of the merkle tree for which this proof
    /// was generated
    pub root: Field,
    /// The actual semaphore proof verifying that the sender
    /// is included in the set of orb verified users
    pub proof: Proof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof(pub semaphore::protocol::Proof);
	  
```

**External Nullifier**

Schema: `vv-mmyyyy-nn`

Version Prefix: `vv`
- Validation: Version matches current version.

Date: `mmyyyy`
- Validation: Month/Year matches current Month Year 

PBH Nonce: `nn`: `u16`
- Validation: PBH Nonce must be ≤ 30 by default. It is used to rate limit the amount of PBH transactions that can be sent in any given month. This value should reset at the beginning of each month monotonically increasing from 0→ `num_pbh_txs` . Any nonce > `num_pbh_txs` set on launch of the builder will be invalidated and not be inserted into the transaction pool.

**Nullifier Hash**
- Validation: Must be unique at the time of transaction validation.

**Root**
- Validation: Must be identical to the `latestRoot` in storage of the `OpWorldId` contract on L2.

Additional Considerations: If a root has not yet been synchronized with l1. There is a window in which a valid proof will be seen as invalid in the transaction validator. A robust approach would be to read the root on l2, and assert it matches the root on l1 prior to sending the transaction to prevent a transaction validation error response.

### PBH Transaction Lifecycle

Because a PBH transaction has a custom transaction envelope this means that a PBH transaction may only be sent to the `world-chain-builder`. Further the transaction will not be peered by the builder to the _sequencer_, or any other clients on the network. 

The `world-chain-builder` implements a custom [WorldChainEthApi](https://github.com/worldcoin/world-chain/blob/c44417727fcf510597aaf247dc1e2d8dca03a3b7/world-chain-builder/src/rpc/mod.rs#L52) that allows it to recieve PBH transaction envelopes over RPC through an `eth_sendRawTransaction` request. If a semaphore proof is attached to the transaction the [WorldChainTransactionValidator](https://github.com/worldcoin/world-chain/blob/c44417727fcf510597aaf247dc1e2d8dca03a3b7/world-chain-builder/src/pool/validator.rs#L37) will first validate the integrity of the proof, and if valid insert the transaction into the transaction pool with an associated bool indicating the pooled transaction is human verified. 

The transaction pool implements a custom [ordering policy](https://github.com/worldcoin/world-chain/blob/c44417727fcf510597aaf247dc1e2d8dca03a3b7/world-chain-builder/src/pool/ordering.rs#L10) which guarantees top of block priority for verified human transactions. 

A percentage of the block space is reserved for pbh transactions as defined by `verified_blockspace_capacity`. This value represents the maximum percentage of the block gas limit that will be dedicated to human verified transactions. If the amount of pbh transactions does not meet the threshold of reserved block space then non-verified transactions will fill this reserved block space. `100 - verified_blockspace_capacity` is the percentage of the block space always dedicated to non-verified transactions.

### Netowrk 
World Chain is a [Optimistic Rollup](https://ethereum.org/en/developers/docs/scaling/optimistic-rollups/) on Ethereum. World Chain functions at the Consensus layer identically to that of Optimism, and other optimistic rollups. But differs at the execution layer in a couple ways. 

In a traditional Optimistic Rollup the _Sequencer_ acts as the sole participant that proposes new blocks. 

On World Chain we have two possible block proposers:

1. `world-chain-builder` - Custom Ordering Policy
2. _sequencer_ - An `op-geth` client constructing blocks with a canonical ordering policy. 

The `world-chain-builder` is the favored proposer in the network. Meaning if the builder produces a valid block the builders block will always be accepted by the network over the sequencers block. 

The sequencer has two jobs:

1. Attest to the integrity of the Block Proposed by the Builder.
2. Fallback such that if the builder produces an invalid payload, times out, or otherwise - The chain still moves forward.

Two proposers on the network sequencing blocks is made possible by utilizing an [engine api](https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md) proxy server multiplexing engine api calls from the consensus layer to both the _sequencer_, and the builder in parallel. We currently use [rollup-boost](https://github.com/flashbots/rollup-boost/tree/main) for this purpose.

For a deep dive into rollup-boost checkout the [design spec](https://github.com/ethereum-optimism/design-docs/blob/main/protocol/external-block-production.md).

### Additional References

[Creating Human Verified Transactions](../crates/toolkit/README.md)

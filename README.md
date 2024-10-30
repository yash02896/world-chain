# World Chain Builder

The WorldChain Builder is a custom block builder for the OP Stack that provides Priority Blockspace for Humans (PBH). PBH enables verified World ID users to execute transactions with top of block priority, enabling a more frictionless user experience. This mechanism is designed to ensure that ordinary users aren’t unfairly disadvantaged by automated systems and greatly mitigates the impact of negative impacts of MEV. PBH also enables future flexibility, allowing for a separate EIP-1559-style fee market mechanism for verified transactions.


## PBH Transaction Envelope
The builder introduces a new EIP-2718 RLP encoded transaction envelope including a [Pbh Payload](https://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/src/pbh/payload.rs#L50), which contains a World ID proof, proving the transaction was created by a verified user.

```rust

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

```

PBH Components

External Nullifier

The External Nullifier is a structured identifier used to ensure the uniqueness and proper sequencing of PBH transactions. Its format is defined as:

Schema: vv-mmyyyy-nn

Version Prefix (vv): Represents the version of the nullifier.

Validation: Must match the current version.

Date (mmyyyy): Represents the month and year.

Validation: Must match the current month and year.

PBH Nonce (nn): A u16 value used to rate-limit PBH transactions.

Validation: The PBH Nonce must be ≤ 30 by default. This nonce is used to limit the number of PBH transactions each user can submit per month. It resets at the beginning of each month, incrementing monotonically from 0 to num_pbh_txs. Any nonce greater than num_pbh_txs will be invalidated and not inserted into the transaction pool.

Nullifier Hash

The Nullifier Hash ensures that each PBH transaction is unique at the time of validation.

Validation: The nullifier hash must be unique during transaction validation to prevent duplicate transactions.

Root

The Root represents the root of the Merkle tree for which the proof was generated.

Validation: Must match the latestRoot stored in the OpWorldId contract on L2.

Additional Considerations: If the root has not yet synchronized with L1, there may be a window where a valid proof is perceived as invalid. To prevent transaction validation errors, the root should be read from L2 and asserted to match the root on L1 before submitting the transaction.


### **Builder API**

The custom PBH transaction envelope must be sent to the builder’s public rpc through a `eth_sendRawTransaction` JSON RPC request. 

Additional References:

[**Building a Raw PBH Transaction Envelope from ORB Sequencer Reference**](https://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/crates/toolkit/README.md)

[**Sending a Raw PBH Transaction to the Builder Reference:**](ttps://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/crates/assertor/src/main.rs#L119)







# Running the Devnet


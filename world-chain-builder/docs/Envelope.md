# World Chain Builder API Spec

### **Transaction Envelope**

The PBH transaction envelope consists of an EIP 2718 RLP encoded transaction envelope concatenated with the RLP encoded `PbhPayload`

References: 
-  [Pbh Payload](https://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/src/pbh/payload.rs#L50)
-  [Pooled Transaction](https://github.com/worldcoin/world-chain/blob/8d60a1e79dbb3be68db075d49b3d0a8a67e45b3e/world-chain-builder/src/primitives.rs#L14)

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

// Raw Transaction Envelope encoding
impl WorldChainPooledTransactionsElement {
		pub fn encode_enveloped(&self, out: &mut dyn alloy_rlp::BufMut) {
		        self.inner.encode_enveloped(out);
		        if let Some(pbh_payload) = &self.pbh_payload {
		            pbh_payload.encode(out);
		        }
		 }
}
	  
```

**External Nullifier**

Schema: `vv-mmyyyy-nn`

Version Prefix: `v1`
> Validation: Version matches current version.

Date: `01-2025`
> Validation: Month/Year matches current Month Year 

PBH Nonce: `u16`:
> Validation: PBH Nonce must be ≤ 30 by default. It is used to rate limit the amount of PBH transactions that can be sent in any given month. This value should reset at the beginning of each month monotonically increasing from 0→ `num_pbh_txs` . Any nonce > `num_pbh_txs` set on launch of the builder will be invalidated and not be inserted into the transaction pool.

**Nullifier Hash**

> Validation: Must be unique at the time of transaction validation.

**Root**

> Validation: Must be identical to the `latestRoot` in storage of the `OpWorldId` contract on L2.

Additional Considerations: If a root has not yet been synchronized with l1. There is a window in which a valid proof will be seen as invalid in the transaction validator. A robust approach would be to read the root on l2, and assert it matches the root on l1 prior to sending the transaction to prevent a transaction validation error response.



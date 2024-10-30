## World Chain Builder

This document is intended to outline at a high level the lifecycle of a PBH Transaction within the `world-chain-builder` as well as the different components involved that make PBH possible within a optimistic rollup. 

### Overview

The `world-chain-builder` is a custom block builder integrated with [world-id](https://world.org/world-id) which implements _Priority Blockspace for Humans (PBH)_. 

The builder defines a custom transaction envelope for PBH transactions while retaining backwards compatibility with standard [EIP 2718 transaction envelope](https://eips.ethereum.org/EIPS/eip-2718). This customn transaction envelope holds a [world-id](https://world.org/world-id) semaphore proof allowing the builder to verify _proof of personhood_ associated with the transaction. 

A detailed outline of the PBH transaction envelope can be found [here](PbhEnvelope.md). 

This custom transaction envelope enables a custom ordering policy during block construction that disjoins the fee markets between orb verified humans, and all other transactions on the network. This significantly mitigates the negative extranalities of Mev, and optimizes time to inclusion for verified humans on world-chain.

### PBH Transaction Lifecycle

Because a PBH transaction has a custom transaction envelope this means that a PBH transaction may only be sent to the `world-chain-builder`. Further the transaction will not be peered by the builder to the _sequencer_, or any other clients on the network. 

The `world-chain-builder` implements a custom [WorldChainEthApi](https://github.com/worldcoin/world-chain/blob/c44417727fcf510597aaf247dc1e2d8dca03a3b7/world-chain-builder/src/rpc/mod.rs#L52) that allows it to recieve PBH transaction envelopes over RPC through an `eth_sendRawTransaction` request. If a semaphore proof is attached to the transaction the [WorldChainTransactionValidator](https://github.com/worldcoin/world-chain/blob/c44417727fcf510597aaf247dc1e2d8dca03a3b7/world-chain-builder/src/pool/validator.rs#L37) will first validate the integrity of the proof, and if valid insert the transaction into the transaction pool with an associated bool indicating the pooled transaction is human verified. 

For a detailed look at the custom transaction envelope, and validation rules see [PBH Transaction Envelope](Envelope.md).


### Additional References
[World Chain Network](Network.md)

[Creating Human Verified Transactions](../crates/toolkit/README.md)

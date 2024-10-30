## World Chain Builder

This document is intended to outline at a high level the lifecycle of a PBH Transaction within the `world-chain-builder` as well as the different components involved that make PBH possible within a optimistic rollup. 

### Overview

The `world-chain-builder` is a custom block builder integrated with [world-id](https://world.org/world-id) which implements _Priority Blockspace for Humans (PBH)_. 

The builder defines a custom transaction envelope for PBH transactions while retaining backwards compatibility with standard [EIP 2718 transaction envelope](https://eips.ethereum.org/EIPS/eip-2718). This customn transaction envelope holds a [world-id](https://world.org/world-id) semaphore proof allowing the builder to verify _proof of personhood_ associated with the transaction. 

A detailed outline of the PBH transaction envelope can be found [here](PbhEnvelope.md). 

This custom transaction envelope enables a custom ordering policy during block construction that disjoins the fee markets between orb verified humans, and all other transactions on the network. This significantly mitigates the negative extranalities of Mev, and optimizes time of inclusion for verified humans on world-chain.

### Appendix
[World Chain Network](Network.md)

[PBH Transaction Envelope](Envelope.md)

[Creating Human Verified Transactions](../crates/toolkit/README.md)

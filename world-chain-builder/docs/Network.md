## Netowrk 
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



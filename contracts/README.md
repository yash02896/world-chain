# PBH Contracts

[Priority blockspace for humans (PBH)](https://github.com/worldcoin/world-chain?tab=readme-ov-file#world-chain-builder) enables verified World ID users to execute transactions with top of block priority, enabling a more frictionless user experience onchain. This mechanism is designed to ensure that ordinary users aren’t unfairly disadvantaged by automated systems and greatly mitigates the negative impact of MEV. Currently, users are able to submit a “PBH Payload” to the World Chain Builder, consisting of an [Ethereum typed transaction](https://eips.ethereum.org/EIPS/eip-2718)  and optional semaphore proof ensuring that the sender is verified World ID user to gain priority inclusion in the next block.

For those unfamiliar, [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) is designed to enable [account abstraction](https://ethereum.org/en/roadmap/account-abstraction/) via an “entry point” contract and “user operations”. A `UserOperation` is a payload that is defined by a user, specifying actions that a “bundler” can execute on their behalf. The `EntryPoint` contract conducts all of the necessary validation logic, executes the user operation onchain and manages any post execution logic (ex. paymaster logic). Users send their `UserOperation` to “bundlers”, which are services that maintain a mempool of many `UserOperation`s, bundling them together to submit them to the blockchain for inclusion.

*Stage 1* 
4337 PBH features `PBHSignatureAggregator`, `PBHEntryPoint`, and `PBH4337Module` contracts.

*PBHEntryPoint*

The `PBHEntryPoint` acts as a proxy in front of the singleton 4337 EntryPoint contract onchain. The builder is able to identify a PBH transaction by the target. For a transaction to be considered PBH, the `to` address of the transaction must be set to the `PBHEntryPoint`. 

The `PBHEntryPoint` contract exposes two functions:

`handleAggregatedOps()` 
- Allows a Bundler to submit a Priority Bundle transaction where the [aggregated signature](https://github.com/eth-infinitism/account-abstraction/blob/b3bae63bd9bc0ed394dfca8668008213127adb62/contracts/interfaces/IEntryPoint.sol#L144) contains a vector encoding of WorldID proof's, and associated proof data to be verified on chain, or by the block builder ordering the block. 

`pbhMulticall()` 
- PBH Multicall additionally allows WorldID verified actors to execute a multicall with top of block inclusion by attaching a valid WorldID proof in the calldata to be verified by the block builder, or on chain. This allows non-4337 individual transactions to get top of block priority. 

*PBHSignatureAggregator*
- The `PBHSignatureAggregator` serves as a utility contract to the bundler to aggregate UserOperation proofs onto the aggregate signature of `handleAggregatedOps`. It also serves as a cryptographic link between the `PBHEntryPoint` guaranteeing a bundler cannot prevent a `PBH` `UserOperation` from being included without priority.

*PBH4337Module*
- The `PBH4337Module` is an extension of the [4337 module](https://github.com/worldcoin/safe-modules/blob/9abf69ea1df673c1010aeb9bbbc6aa14124ba425/modules/4337/contracts/Safe4337Module.sol) that returns a custom validation path based on the nonce key signed over by the signatory of the user operation. The validation path returned from `_validateSignatures` allows the bundler to seemlessly group Priority UserOperations on the `PBHSignatureAggregator`. 

Signature Scheme:
```
Bytes [0 : 12] Timestamp Validation Data
Bytes [12 : 65 * signatureThreshold + 12] ECDSA Signatures
Bytes [65 * signatureThreshold + 12 : 65 * signatureThreshold + 364] ABI Encoded Proof Data
```



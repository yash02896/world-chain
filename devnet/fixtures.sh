#!/bin/bash
set -e
MNEMONIC="test test test test test test test test test test test junk"
BUILDER_SOCKET="http://localhost:54542"
export IDENTITY=11ff11
export INCLUSION_PROOF_URL="https://signup-orb-ethereum.stage-crypto.worldcoin.dev/inclusionProof"

SIGNERS=()

i=({0..5})
for x in "${i[@]}"; do
    SIGNERS+=($(echo $(cast wallet private-key --mnemonic "${MNEMONIC}" --mnemonic-index $x)))
done

TRANSACTIONS=()
for s in "${SIGNERS[@]}"; do
    TRANSACTIONS+=($(echo $(cast mktx --private-key $s 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF --value 1ether --rpc-url $BUILDER_SOCKET)))
done

FIXTURE=()

cd "${PWD}/../world-chain-builder"
pbh_nonces=({0..15})
for t in "${TRANSACTIONS[@]}"; do
    for i in "${pbh_nonces[@]}"; do
        FIXTURE+=($(echo $("${PWD}/../world-chain-builder/x" prove -t $t -N $i)))
    done
done

cd "${PWD}/../devnet"

# Write the fixture
jq -nc '{fixture: $ARGS.positional}' --args ${FIXTURE[@]} >> "${PWD}/fixtures/fixture.json"

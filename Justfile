set positional-arguments

# default recipe to display help information
default:
    @just --list

# Spawns the devnet
devnet-up:
    @just ./devnet/devnet-up

# Stops the devnet **This will prune all docker containers**
devnet-down:
    @just ./devnet/devnet-down

# Builds and tags the world-chain-builder image
build:
    @just ./devnet/build

# Tests the world-chain-builder
test:
    @just ./world-chain-builder/test

# Formats the world-chain-builder
fmt:
    @just ./world-chain-builder/fmt

# Runs the block building assertions
# NOTE: The devnet needs to be running for this to work
assertor *args='':
    @just ./world-chain-builder/assertor $@

fixtures:
    @just ./devnet/fixtures
use std::{collections::BTreeMap, sync::Arc};

use parking_lot::RwLock;
use reth_primitives::SealedBlock;
use reth_provider::{BlockReaderIdExt, ProviderResult, StateProviderFactory};
use revm_primitives::{address, Address, U256};
use semaphore::Field;

/// The WorldID contract address.
pub const OP_WORLD_ID: Address = address!("42ff98c4e85212a5d31358acbfe76a621b50fc02");
/// The slot of the `_latestRoot` in the WorldID contract.
pub const LATEST_ROOT_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// A provider for managing and validating World Chain roots.
#[derive(Debug, Clone)]
pub struct RootProvider<Client>
where
    Client: StateProviderFactory + BlockReaderIdExt,
{
    /// The client used to aquire account state from the database.
    client: Client,
    /// A map of valid roots indexed by block timestamp.
    valid_roots: BTreeMap<u64, Field>,
    /// The timestamp of the latest valid root.
    latest_valid_timestamp: u64,
    /// The period after which a root is considered expired.
    expiration_period: u64,
}

/// TODO: Handle Reorgs
impl<Client> RootProvider<Client>
where
    Client: StateProviderFactory + BlockReaderIdExt,
{
    /// Creates a new RootProvider instance.
    ///
    /// # Arguments
    ///
    /// * `client` - The client used to aquire account state from the database.
    /// * `expiration_period` - The period after which a root is considered expired.
    pub fn new(client: Client, expiration_period: u64) -> Self {
        Self {
            client,
            valid_roots: BTreeMap::new(),
            latest_valid_timestamp: 0,
            expiration_period,
        }
    }

    /// Commits any changes to the state.
    ///
    /// # Arguments
    ///
    /// * `block` - The new block to be committed.
    ///
    /// # Returns
    ///
    /// A `ProviderResult<()>` indicating success or failure.
    fn on_new_block(&mut self, block: &SealedBlock) -> ProviderResult<()> {
        let state = self.client.state_by_block_hash(block.hash())?;
        let root = state.storage(OP_WORLD_ID, LATEST_ROOT_SLOT.into())?;

        if let Some(root) = root {
            self.valid_roots.insert(block.header.timestamp, root);
            self.latest_valid_timestamp = block.header.timestamp;
            self.purge_invalid();
        } else {
            // We missed a block, we need to find the last valid root
            if self.valid_roots.is_empty() {
                // TODO:
            }
        }

        Ok(())
    }

    /// Purges all roots that are older than the expiration period.
    fn purge_invalid(&mut self) {
        if self.latest_valid_timestamp > self.expiration_period {
            self.valid_roots.retain(|timestamp, _| {
                *timestamp >= self.latest_valid_timestamp - self.expiration_period
            });
        };
    }

    /// Returns a vector of all valid roots.
    ///
    /// # Returns
    ///
    /// A `Vec<Field>` containing all valid roots.
    fn roots(&self) -> Vec<Field> {
        self.valid_roots.values().cloned().collect()
    }
}

/// A validator for World Chain roots.
#[derive(Debug, Clone)]
pub struct WorldChainRootValidator<Client>
where
    Client: StateProviderFactory + BlockReaderIdExt,
{
    /// The RootProvider used for caching and managing roots.
    cache: Arc<RwLock<RootProvider<Client>>>,
}

impl<Client> WorldChainRootValidator<Client>
where
    Client: StateProviderFactory + BlockReaderIdExt,
{
    /// Creates a new WorldChainRootValidator instance.
    ///
    /// # Arguments
    ///
    /// * `client` - The client used for state and block operations.
    /// * `expiration_period` - The period after which a root is considered expired.
    ///
    /// # Returns
    ///
    /// A new `WorldChainRootValidator<Client>` instance.
    pub fn new(client: Client, expiration_period: u64) -> Self {
        let cache = RootProvider::new(client, expiration_period);

        Self {
            cache: Arc::new(RwLock::new(cache)),
        }
    }

    /// Validates a given root.
    ///
    /// # Arguments
    ///
    /// * `root` - The root to be validated.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the root is valid.
    pub fn validate_root(&self, root: Field) -> bool {
        self.cache.read().roots().contains(&root)
    }

    /// Commits a new block to the validator.
    ///
    /// # Arguments
    ///
    /// * `block` - The new block to be committed.
    ///
    /// # Returns
    ///
    /// A `ProviderResult<()>` indicating success or failure.
    pub fn on_new_block(&self, block: &SealedBlock) {
        if let Err(e) = self.cache.write().on_new_block(block) {
            tracing::error!("Failed to commit new block: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    impl<Client> WorldChainRootValidator<Client>
    where
        Client: StateProviderFactory + BlockReaderIdExt,
    {
        pub fn set_client(&mut self, client: Client) {
            self.cache.write().set_client(client);
        }
    }

    impl<Client> RootProvider<Client>
    where
        Client: StateProviderFactory + BlockReaderIdExt,
    {
        pub fn set_client(&mut self, client: Client) {
            self.client = client;
        }
    }
}

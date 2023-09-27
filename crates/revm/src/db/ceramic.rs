use crate::primitives::{AccountInfo, Bytecode, B160, B256, KECCAK_EMPTY, U256};
use crate::Database;
use ethers_core::types::{BlockId, H160 as eH160, H256, U64 as eU64};
use ethers_providers::Middleware;
use std::sync::Arc;
use ceramic_http_client::ceramic_event::Signer;
use tokio::runtime::{Handle, Runtime};
use crate::db::EthersDB;
use ceramic_http_client::remote::CeramicRemoteHttpClient;

pub struct CeramicDB<M: Middleware, S: Signer> {
    ceramic_client: CeramicRemoteHttpClient<S>,
    ethers: EthersDB<M>,
}

impl<M: Middleware, S: Signer> CeramicDB<M, S> {
    pub fn new(ceramic_client: CeramicRemoteHttpClient<S>, client: Arc<M>, block_number: Option<BlockId>) -> Option<Self> {
        EthersDB::new(client, block_number).map(|ethers| {
            Self {
                ceramic_client,
                ethers,
            }
        })
    }

    /// internal utility function to call tokio feature and wait for output
    fn block_on<F: core::future::Future>(&self, f: F) -> F::Output {
        match self.ethers.runtime() {
            Some(runtime) => runtime.block_on(f),
            None => futures::executor::block_on(f),
        }
    }

    pub fn block_number(&self) -> &Option<BlockId> {
        self.ethers.block_number()
    }
}

impl<M: Middleware, S: Signer> Database for CeramicDB<M, S> {
    type Error = ();

    fn basic(&mut self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        let add = eH160::from(address.0);
        let ethers_client = self.ethers.client();

        let f = async {
            let nonce = ethers_client.get_transaction_count(add, *self.block_number());
            let balance = ethers_client.get_balance(add, *self.block_number());
            let code = ethers_client.get_code(add, *self.block_number());
            tokio::join!(nonce, balance, code)
        };
        let (nonce, balance, code) = self.block_on(f);
        // panic on not getting data?
        let bytecode = Bytecode::new_raw(
            code.unwrap_or_else(|e| panic!("ceramic get code error: {e:?}"))
                .0,
        );
        let code_hash = bytecode.hash_slow();
        Ok(Some(AccountInfo::new(
            U256::from_limbs(
                balance
                    .unwrap_or_else(|e| panic!("ceramic ethers get balance error: {e:?}"))
                    .0,
            ),
            nonce
                .unwrap_or_else(|e| panic!("ceramic ethers get nonce error: {e:?}"))
                .as_u64(),
            code_hash,
            bytecode,
        )))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
        // not needed because we already load code with basic info
    }

    fn storage(&mut self, address: B160, index: U256) -> Result<U256, Self::Error> {
        let add = eH160::from(address.0);
        let index = H256::from(index.to_be_bytes());
        let f = async {
            let storage = self
                .ethers
                .client()
                .get_storage_at(add, index, *self.block_number())
                .await
                .unwrap();
            U256::from_be_bytes(storage.to_fixed_bytes())
        };
        Ok(self.block_on(f))
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        // saturate usize
        if number > U256::from(u64::MAX) {
            return Ok(KECCAK_EMPTY);
        }
        let number = eU64::from(u64::try_from(number).unwrap());
        let f = async {
            self.ethers
                .client()
                .get_block(BlockId::from(number))
                .await
                .ok()
                .flatten()
        };
        Ok(B256(self.block_on(f).unwrap().hash.unwrap().0))
    }
}

// Run tests with `cargo test -- --nocapture` to see print statements
#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::types::U256 as eU256;
    use ethers_providers::{Http, Provider};
    use std::str::FromStr;
    use ceramic_http_client::ceramic_event::{DidDocument, JwkSigner};
    use ceramic_http_client::remote::Url;

    async fn get_client() -> CeramicDB<Provider<Http>, JwkSigner> {
        let s = signer().await;
        let url = Url::parse("http://localhost:7007").unwrap();
        let ceramic_client = CeramicRemoteHttpClient::new(s, url);
        let client = Provider::<Http>::try_from(
            "https://mainnet.infura.io/v3/c60b0bb42f8a4c6481ecd229eddaca27",
        )
            .unwrap();
        let client = Arc::new(client);

        CeramicDB::new(ceramic_client, Arc::clone(&client), Some(BlockId::from(16148323))).unwrap()
    }

    async fn signer() -> JwkSigner {
        let s = std::env::var("DID_DOCUMENT").unwrap_or_else(|_| {
            "did:key:z6MkeqCTPhHPVg3HaAAtsR7vZ6FXkAHPXEbTJs7Y4CQABV9Z".to_string()
        });
        JwkSigner::new(
            DidDocument::new(&s),
            &std::env::var("DID_PRIVATE_KEY").unwrap(),
        )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn can_get_basic() {
        let mut ceramic_client = get_client().await;

        // ETH/USDT pair on Uniswap V2
        let address = "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852"
            .parse::<eH160>()
            .unwrap();
        let address = address.as_fixed_bytes().into();

        let acc_info = ceramic_client.basic(address).unwrap().unwrap();

        // check if not empty
        assert!(acc_info.exists());
    }

    #[tokio::test]
    async fn can_get_storage() {
        let mut ceramic_client = get_client().await;

        // ETH/USDT pair on Uniswap V2
        let address = "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852"
            .parse::<eH160>()
            .unwrap();
        let address = address.as_fixed_bytes().into();

        // select test index
        let index = U256::from(5);
        let storage = ceramic_client.storage(address, index).unwrap();

        // https://etherscan.io/address/0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852#readContract
        // storage[5] -> factory: address
        let actual = U256::from_limbs(eU256::from("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f").0);

        assert_eq!(storage, actual);
    }

    #[tokio::test]
    async fn can_get_block_hash() {
        let mut ceramic_client = get_client().await;

        // block number to test
        let block_num = U256::from(16148323);
        let block_hash = ceramic_client.block_hash(block_num).unwrap();

        // https://etherscan.io/block/16148323
        let actual =
            B256::from_str("0xc133a5a4ceef2a6b5cd6fc682e49ca0f8fce3f18da85098c6a15f8e0f6f4c2cf")
                .unwrap();

        assert_eq!(block_hash, actual);
    }
}

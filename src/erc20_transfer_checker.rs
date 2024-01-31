//! ERC Transfer checker

use async_trait::async_trait;

use crate::types::{
    EvmTransactionChecker, EvmTransactionCheckerContext, EvmTransactionCheckerResult,
};

use crate::erc20::{
    ContractAddress, ERC20Method,
};

use ethers::types::H160;
use std::str::FromStr;
use anyhow::Context;
use ethers::utils::hex;

/// Erc20TransferChecker is used to check if a transaction is a likely safe ERC20 transfer.
pub struct Erc20TransferChecker {}

#[async_trait]
impl EvmTransactionChecker for Erc20TransferChecker {
    fn name(&self) -> &'static str {
        "er20-transfer-checker"
    }

    async fn run(
        &self,
        _context: &EvmTransactionCheckerContext,
    ) -> anyhow::Result<EvmTransactionCheckerResult> {
        let mut result = EvmTransactionCheckerResult::default();

        let transaction = _context.transaction;
        
        // Parse the EVM transaction object
        let data = transaction.data.as_ref()
            .context("Transaction data is missing")?;
        let to_address = transaction.to.as_ref()
            .context("To address is missing")?;

        if let Some(warning) = check_erc20_transfer_to_token_contract(data, to_address)? {
            result.warnings.push(warning);
        }

        if let Some(warning) = check_erc20_maximum_allowance(data)? {
            result.warnings.push(warning);
        }

        Ok(result)
    }
}

/// If the method call is an `Approve` and the approved amount is maximum (2^256 - 1),
/// it generates a warning indicating that the spender can withdraw any amount at any time.
fn check_erc20_maximum_allowance(data: &str) -> anyhow::Result<Option<String>> {
    let data_bytes = hex::decode(data)
        .context("Failed to decode transaction data from hexadecimal")?;

    // Assume for now that empty data objects (eth_send) are not ERC20 transfers and therefore don't endanger ERC assets
    if data_bytes.len() < 4 {
        return Ok(None);
    }

    let method = &data_bytes[0..4];
    let method_vec = method.to_vec();
    let erc20_method = ERC20Method::from(method_vec);

    if erc20_method == ERC20Method::Approve && data_bytes.len() >= 36 {
        let approved_amount = &data_bytes[36..68];
        let max_allowance = [255u8; 32];

        if approved_amount == &max_allowance[..] {
            let warning = "ERC20 maximum allowance given. The spender can withdraw any amount at any time.".to_string();
            return Ok(Some(warning));
        }
    }

    Ok(None)
}

/// If the method call is a `Transfer` and the destination address is identified as a token contract address
/// (not an EOA), it generates a warning indicating tokens may be lost forever (e.g. in contracts like WETH)
fn check_erc20_transfer_to_token_contract(data: &str, to_address: &str) -> anyhow::Result<Option<String>> {
    let to_address_bytes = H160::from_str(to_address)
        .context("Failed to parse to_address to H160")?;

    let data_bytes = hex::decode(data)
        .context("Failed to decode transaction data from hexadecimal")?;

    // Assume for now that empty data objects (eth_send) are not ERC20 transfers and therefore don't endanger ERC assets
    if data_bytes.len() < 4 {
        return Ok(None);
    }

    let method = &data_bytes[0..4];
    let method_vec = method.to_vec();
    let erc20_method = ERC20Method::from(method_vec);
    let token_contract_address = ContractAddress::from(to_address_bytes);

    if erc20_method == ERC20Method::Transfer && token_contract_address != ContractAddress::Unidentified(to_address_bytes) {
        let warning = format!(
            "ERC20 transfer to token contract address {:?}",
            token_contract_address
        );
        return Ok(Some(warning));
    }

    Ok(None)
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EvmTransactionObject;

    #[tokio::test]
    async fn it_does_not_warn_when_no_erc20_transfer() -> anyhow::Result<()> {
        // Vitalik wraps some ETH to WETH by sending it to the contract
        let transaction = EvmTransactionObject {
            from: Some("0xd8da6bf26964af9d7eed9e03e53415d37aa96045".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()),
            data: Some("0x".to_string()),
            value: Some("1000000000000000000".to_string()),
            gas: None,
        };
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;

        assert!(result.warnings.is_empty(), "no warnings on ETH transfer");

        Ok(())
    }

    #[tokio::test]
    async fn it_should_warn_when_erc20_transfer() -> anyhow::Result<()> {
        // Vitalik attempts to unwrap WETH by sending WETH to the contract (sample case, can work with other listed tokens)
        let transaction = EvmTransactionObject {
            from: Some("0xd8da6bf26964af9d7eed9e03e53415d37aa96045".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()),
            data: Some("0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa9604501".to_string()), // Emulates an ERC20 transfer call
            value: Some("0".to_string()),
            gas: None,
        };
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;

        assert!(!result.warnings.is_empty(), "warning on ERC20 transfer");
        Ok(())
    }

    #[tokio::test]
    async fn it_should_warn_if_max_allowance_given() -> anyhow::Result<()> {
        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string()),
            data: Some("0x095ea7b30000000000000000000000006b175474e89094c44da98b954eedeac495271d0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()),
            value: Some("0".to_string()),
            gas: None,
        };

        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;
        
        assert!(!result.warnings.is_empty(), "warning on ERC20 transfer");
        Ok(())
    }
}

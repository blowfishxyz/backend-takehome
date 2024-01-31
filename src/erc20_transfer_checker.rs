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
        
        let data = transaction.data.as_ref()
            .context("Transaction data is missing")?;
        let to_address = transaction.to.as_ref()
            .context("To address is missing")?;

        let to_address_bytes = H160::from_str(to_address)
            .context("Failed to parse to_address to H160")?;

        let data_bytes = hex::decode(data)
            .context("Failed to decode transaction data from hexadecimal")?;

        // Return ok for now if no transfer data
        if data.len() < 4 {
            return Ok(result);
        }
        let method = &data[0..4];

        println!("Method: {:?}", method);

        let method = &data_bytes[0..4];
        let method_vec = method.to_vec();
        let erc20_method = ERC20Method::from(method_vec);
        let contract_address = ContractAddress::from(to_address_bytes);

        println!("ERC20 method: {:?}", erc20_method);
        println!("Contract address: {:?}", contract_address);

        if erc20_method == ERC20Method::Transfer && contract_address != ContractAddress::Unidentified(to_address_bytes) {
            result.warnings.push(format!(
                "ERC20 transfer to contract address {:?}",
                contract_address
            ));
        }
        
        // Check if the tx gives ERC20 approval to a proxy contract
        println!("Result: {:?}", result);
        Ok(result)
    }
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
}
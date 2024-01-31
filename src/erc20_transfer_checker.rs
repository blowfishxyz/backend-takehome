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
        let from_address = transaction.from.as_ref()
            .context("From address is missing")?;

        let warnings = [
            check_erc20_transfer_to_token_contract(data, to_address),
            check_erc20_maximum_allowance(data),
            check_for_scam_addresses(from_address, data),
        ];

        for warning in warnings {
            match warning {
                Ok(Some(warning)) => result.warnings.push(warning),
                Ok(None) => (),
                Err(e) => return Err(e),
            }
        }

        Ok(result)
    }
}

/// If the method call is an `Approve` or `Permit` and the approved amount is maximum (2^256 - 1),
/// it generates a warning indicating that the spender can withdraw any amount at any time.
fn check_erc20_maximum_allowance(data: &str) -> anyhow::Result<Option<String>> {
    let data_bytes = hex::decode(data)
        .context("Failed to decode transaction data from hexadecimal")?;

    // Assume for now that empty data objects (eth_send) are not ERC20 transfers and therefore don't endanger ERC assets
    if data_bytes.len() < 4 {
        return Ok(None);
    }

    // Assume for now that the method is the first 4 bytes of the data
    let method = &data_bytes[0..4];
    let method_vec = method.to_vec();
    let erc20_method = ERC20Method::from(method_vec);

    if erc20_method == ERC20Method::Approve && data_bytes.len() >= 36 {
        // Approve method signature is 4 bytes, spender is 20 bytes, value is 32 bytes
        // Therefore, use byterange 36 to 68
        let approved_amount = &data_bytes[36..68];
        let max_allowance = [255u8; 32];

        if approved_amount == &max_allowance[..] {
            let warning = "ERC20 maximum allowance given. The spender can withdraw any amount at any time.".to_string();
            return Ok(Some(warning));
        }
    }

    if erc20_method == ERC20Method::Permit && data_bytes.len() >= 100 {
        // Permit method signature is 4 bytes, owner is 20 bytes, spender is 20 bytes, value is 32 bytes
        // Therefore, use byterange 44 to 76
        let approved_amount = &data_bytes[44..76];
        let max_allowance = [255u8; 32];

        println!("approved_amount: {:?}", approved_amount);
        println!("max_allowance: {:?}", max_allowance);
    
        if approved_amount == &max_allowance[..] {
            let warning = "ERC20 maximum allowance given via Permit. The spender can withdraw any amount at any time.".to_string();
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

/// Checks if the argument of any potentially balance-altering functions is a known scam address and generates a warning if it is.
fn check_for_scam_addresses(from: &str, data: &str) -> anyhow::Result<Option<String>> {
    let known_scam_addresses = vec![
        "d8da6bf26964af9d7eed9e03e53415d37aa96045", // Example scam address
    ];

    println!("data: {}", data);

    let data_bytes = hex::decode(data)
        .context("Failed to decode transaction data from hexadecimal")?;
    
    if data_bytes.len() < 36 {
        return Ok(None);
    }

    let method = &data_bytes[0..4];
    let method_vec = method.to_vec();
    let erc20_method = ERC20Method::from(method_vec);

    // Handle case: ERC20 transfer // approve, to_address from bytes 16 to 36
    if erc20_method != ERC20Method::Transfer && erc20_method != ERC20Method::Approve {
        return Ok(None);
    }

    let to_address = &data_bytes[16..36];
    let to_address_str = hex::encode(to_address);

    if known_scam_addresses.contains(&to_address_str.to_lowercase().as_str()) {
        let warning = format!("Warning: The destination address {} is a known scam address. Proceed with caution.", to_address_str);
        return Ok(Some(warning));
    }

    // Handle case: ERC20 transferFrom, from_address from bytes 36 to 68
    if erc20_method != ERC20Method::TransferFrom {
        return Ok(None);
    }

    let from_address = &data_bytes[36..68];
    let from_address_str = hex::encode(from_address);

    if &from_address_str == from {
        let warning = format!("Warning: The source address {} is a known scam address. Proceed with caution.", from_address_str);
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
    async fn it_should_warn_if_max_allowance_given_approve() -> anyhow::Result<()> {
        // Works for approve
        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()),
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

    #[tokio::test]
    async fn it_should_warn_if_max_allowance_given_permit() -> anyhow::Result<()> {
        // Works for permit
        let method_signature = "d5e08e95"; // permit method signature
        let owner = "6b175474e89094c44da98b954eedeac495271d0f";
        let spender = "d8da6bf26964af9d7eed9e03e53415d37aa96045";
        let value = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // Max value
        let deadline = "000000005f5e1000"; // Replace with actual future timestamp
        let v = "1c"; // Example value for v (27 or 28, or 0 or 1 for EIP-155)
        let r = "0000000000000000000000000000000000000000000000000000000000000000"; // Some bytes representing r-field
        let s = "0000000000000000000000000000000000000000000000000000000000000000"; // Some bytes representing s-field

        let permit_data = format!(
            "0x{}{}{}{}{}{}{}{}",
            method_signature, owner, spender, value, deadline, v, r, s
        );
        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            // On OZ ERC20 tokens, the permit method is used instead of approve
            to: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            data: Some(permit_data),
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
    async fn it_should_warn_if_scam_address() -> anyhow::Result<()> {
        // Example transaction representing an ERC20 `approve` method call
        // where the spender is a known scam address
        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()), // Address of the ERC20 token contract
            data: Some(
                "0x095ea7b3000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000000000011"
                    .to_string()),
            value: Some("0".to_string()),
            gas: None,
        };
        
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;
        
        assert!(!result.warnings.is_empty(), "warning on ERC20 approve to scam address");
        Ok(())
    }
}

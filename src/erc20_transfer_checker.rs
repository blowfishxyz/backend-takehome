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
use futures::future::{FutureExt, join_all};

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
        
        // Input checks on transaction object
        if transaction.data.is_none() || transaction.to.is_none() || transaction.from.is_none() {
            return Ok(result);
        }
        
        // Parse the EVM transaction object once
        let data_bytes = hex::decode(transaction.data.as_ref().context("Transaction data is missing")?)
            .context("Failed to decode transaction data from hexadecimal")?;
        let to_address_bytes = H160::from_str(transaction.to.as_ref().context("To address is missing")?)
            .context("Failed to parse to_address to H160")?;

        // Run the checks in parallel
        let checks = vec![
            check_erc20_maximum_allowance(&data_bytes).boxed(),
            check_erc20_transfer_to_token_contract(&data_bytes, to_address_bytes).boxed(),
            check_for_scam_addresses(&data_bytes).boxed(),
            check_burn(&data_bytes).boxed(),
        ];

        let warnings = join_all(checks).await;
        
        for warning_result in warnings {
            match warning_result {
                Ok(warning) => {
                    if let Some(warning_message) = warning {
                        result.warnings.push(warning_message);
                    }
                },
                Err(e) => {
                    return Err(anyhow::anyhow!("Error while running checks: {}", e));
                }
            }
        }
        
        Ok(result)
    }
}

/// If the method call is an `Approve` or `Permit` and the approved amount is maximum (2^256 - 1),
/// it generates a warning indicating that the spender can withdraw any amount at any time.
async fn check_erc20_maximum_allowance(data_bytes: &[u8]) -> anyhow::Result<Option<String>> {
    // Assume for now that empty data objects (eth_send) are not ERC20 transfers and therefore don't endanger ERC assets
    if data_bytes.len() < 4 {
        return Ok(None);
    }

    // Assume for now that the method is the first 4 bytes of the data
    let method = &data_bytes[0..4];
    let erc20_method = ERC20Method::from(method.to_vec());

    match erc20_method {
        ERC20Method::Approve if data_bytes.len() >= 36 => {
            // Approve method signature is 4 bytes, spender is 20 bytes, value is 32 bytes
            // Therefore, use byterange 36 to 68
            let approved_amount = &data_bytes[36..68];
            let max_allowance = [255u8; 32];

            if approved_amount == &max_allowance[..] {
                let warning = "ERC20 maximum allowance given. The spender can withdraw any amount at any time.".to_string();
                return Ok(Some(warning));
            }
        },
        ERC20Method::Permit if data_bytes.len() >= 100 => {
            // Permit method signature is 4 bytes, owner is 20 bytes, spender is 20 bytes, value is 32 bytes
            // Therefore, use byterange 44 to 76
            let approved_amount = &data_bytes[44..76];
            let max_allowance = [255u8; 32];

            if approved_amount == &max_allowance[..] {
                let warning = "ERC20 maximum allowance given via Permit. The spender can withdraw any amount at any time.".to_string();
                return Ok(Some(warning));
            }
        },
        _ => {}
    }

    Ok(None)
}

/// If the method call is a `Transfer` and the destination address is identified as a token contract address
/// (not an EOA), it generates a warning indicating tokens may be lost forever (e.g. in contracts like WETH)
async fn check_erc20_transfer_to_token_contract(data_bytes: &Vec<u8>, to_address_bytes: H160) -> anyhow::Result<Option<String>> {
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

    /* TODO: Add checks against any other non-ERC223 supporting tokens */

    Ok(None)
}

/// If the method call is a transfer function and the destination address is a zero address, 
/// it generates a warning indicating tokens may not be transferred as expected.
async fn check_burn(data_bytes: &Vec<u8>) -> anyhow::Result<Option<String>> {
    if data_bytes.len() < 4 {
        return Ok(None);
    }
    
    let method = &data_bytes[0..4];
    let method_vec = method.to_vec();
    let erc20_method = ERC20Method::from(method_vec);

    match erc20_method {
        ERC20Method::Transfer => {
            if data_bytes.len() < 36 {
                return Ok(None);
            }

            // Transfer method signature is 4 bytes, to address is 20 bytes, value is 32 bytes
            // Therefore, use byterange 4 to 24 to get the to address
            let to_address = &data_bytes[4..24];
            let zero_address = [0u8; 20];

            if to_address == &zero_address[..] {
                let warning = "Warning: Transfer called with a zero address as the destination. Tokens may not be transferred as expected.".to_string();
                return Ok(Some(warning));
            }
        },
        ERC20Method::TransferFrom => {
            // TransferFrom method signature is 4 bytes, from address is 20 bytes, to address is 20 bytes, value is 32 bytes
            // Therefore, use byterange 36 to 68 to get the from address
            let from_address = &data_bytes[36..68];
            let zero_address = [0u8; 32];

            if from_address == &zero_address[..] {
                let warning = "Warning: TransferFrom called with a zero address as the source. Tokens may not be transferred as expected.".to_string();
                return Ok(Some(warning));
            }
        },
        _ => {}
    }

    Ok(None)
}

/// Checks if the argument of any potentially balance-altering functions is a known scam address and generates a warning if it is.
/// Scam addresses are typically contracts that will not allow you to withdraw your funds. 
async fn check_for_scam_addresses(data_bytes: &Vec<u8>) -> anyhow::Result<Option<String>> {
    // TODO: Perhaps cache this in the future via. constructor
    let known_scam_addresses = vec![
        "d8da6bf26964af9d7eed9e03e53415d37aa96045", // Example scam address
    ];
    
    if data_bytes.len() < 4 {
        return Ok(None);
    }

    let method = &data_bytes[0..4];
    let erc20_method = ERC20Method::from(method.to_vec());

    match erc20_method {
        ERC20Method::Transfer | ERC20Method::Approve => {
            // Transfer method signature is 4 bytes, to address is 20 bytes (32 bytes total, 0 padded to the right), value is 32 bytes
            // Same with approve
            let to_address = &data_bytes[16..36];
            let to_address_str = hex::encode(to_address);

            if known_scam_addresses.contains(&to_address_str.to_lowercase().as_str()) {
                let warning = format!("Warning: The destination address {} is a known scam address. Proceed with caution.", to_address_str);
                return Ok(Some(warning));
            }
        },
        ERC20Method::TransferFrom => {
            // TransferFrom method signature is 4 bytes, from address is 20 bytes, to address is 20 bytes, value is 32 bytes
            let padded_to_address = &data_bytes[36..68];
            let to_address = &padded_to_address[12..32]; // last 20 bytes of the 32-byte segment
            let to_address_str = hex::encode(to_address);

            if known_scam_addresses.contains(&to_address_str.to_lowercase().as_str()) {
                let warning = format!("Warning: The destination address {} is a known scam address. Proceed with caution.", to_address_str);
                return Ok(Some(warning));
            }
        },
        _ => (),
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
        let method_id = "a9059cbb"; // ERC20 transfer method ID
        let recipient = "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"; // 32 bytes recipient address
        let amount = "0000000000000000000000000000000000000000000000000000000000000001"; // 32 bytes amount (1 token, for simplicity)
        let data = format!("0x{}{}{}", method_id, recipient, amount); // Constructing the data field explicitly

        let transaction = EvmTransactionObject {
            from: Some("0xd8da6bf26964af9d7eed9e03e53415d37aa96045".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()),
            data: Some(data),
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
        let method_id = "095ea7b3"; // ERC20 approve method ID
        let spender = "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f"; // 32 bytes spender address
        let amount = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // 32 bytes amount (max value)
        let data = format!("0x{}{}{}", method_id, spender, amount); // Constructing the data field explicitly

        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()),
            data: Some(data),
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
    async fn it_should_warn_if_scam_address_approve() -> anyhow::Result<()> {
        // Example transaction representing an ERC20 `approve` method call
        // where the spender is a known scam address
        let method_signature = "095ea7b3"; // approve method signature
        let spender = "d8da6bf26964af9d7eed9e03e53415d37aa96045"; // Known scam address
        let value = "0000000000000000000000000000000000000000000000000000000000000011"; // Example value
        // Constructing the data more explicitly
        let data = format!(
            "0x{}000000000000000000000000{}{}",
            method_signature, spender, value
        );

        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()), // Address of the ERC20 token contract
            data: Some(data),
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

    #[tokio::test]
    async fn it_should_warn_if_transfer_to_scam_address() -> anyhow::Result<()> {
        // Example transaction representing an ERC20 `transfer` method call
        // where the recipient is a known scam address
        let method_signature = "a9059cbb"; // transfer method signature
        let recipient = "d8da6bf26964af9d7eed9e03e53415d37aa96045"; // Known scam address
        let value = "0000000000000000000000000000000000000000000000000000000000000011"; // Example value
        // Constructing the data more explicitly
        let data = format!(
            "0x{}000000000000000000000000{}{}",
            method_signature, recipient, value
        );

        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()), // Address of the ERC20 token contract
            data: Some(data),
            value: Some("0".to_string()),
            gas: None,
        };
        
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;
        
        assert!(!result.warnings.is_empty(), "warning on ERC20 transfer to scam address");
        Ok(())
    }

    #[tokio::test]
    async fn it_should_warn_if_transfer_from_to_scam_address() -> anyhow::Result<()> {
        // Example transaction representing an ERC20 `transferFrom` method call
        // where the recipient is a known scam address
        let method_signature = "23b872dd"; // transferFrom method signature
        let source = "6b175474e89094c44da98b954eedeac495271d0f"; // Known source address
        let recipient = "d8da6bf26964af9d7eed9e03e53415d37aa96045"; // Known scam address
        let value = "0000000000000000000000000000000000000000000000000000000000000011"; // Example value
        // Constructing the data more explicitly
        let data = format!(
            "0x{}000000000000000000000000{}000000000000000000000000{}{}",
            method_signature, source, recipient, value
        );

        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()), // Address of the ERC20 token contract
            data: Some(data),
            value: Some("0".to_string()),
            gas: None,
        };
        
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;
        
        assert!(!result.warnings.is_empty(), "warning on ERC20 transferFrom to scam address");
        Ok(())
    }

    #[tokio::test]
    async fn it_should_warn_if_transfer_to_zero_address() -> anyhow::Result<()> {
        // Example transaction representing an ERC20 `transfer` method call
        // where the recipient is a zero address
        let method_signature = "a9059cbb"; // transfer method signature
        let recipient = "0000000000000000000000000000000000000000"; // Zero address
        let value = "0000000000000000000000000000000000000000000000000000000000000011"; // Example value
        // Constructing the data more explicitly
        let data = format!(
            "0x{}000000000000000000000000{}{}",
            method_signature, recipient, value
        );

        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()), // Address of the ERC20 token contract
            data: Some(data),
            value: Some("0".to_string()),
            gas: None,
        };
        
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;
        
        assert!(!result.warnings.is_empty(), "warning on ERC20 transfer to zero address");
        Ok(())
    }

    #[tokio::test]
    async fn it_should_warn_if_transfer_from_to_zero_address() -> anyhow::Result<()> {
        // Example transaction representing an ERC20 `transferFrom` method call
        // where the recipient is a zero address
        let method_signature = "23b872dd"; // transferFrom method signature
        let source = "d8da6bf26964af9d7eed9e03e53415d37aa96045"; // Known scam address
        let recipient = "0000000000000000000000000000000000000000"; // Zero address
        let value = "0000000000000000000000000000000000000000000000000000000000000011"; // Example value
        // Constructing the data more explicitly
        let data = format!(
            "0x{}000000000000000000000000{}000000000000000000000000{}{}",
            method_signature, source, recipient, value
        );

        let transaction = EvmTransactionObject {
            from: Some("0x6b175474e89094c44da98b954eedeac495271d0f".to_string()),
            to: Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()), // Address of the ERC20 token contract
            data: Some(data),
            value: Some("0".to_string()),
            gas: None,
        };
        
        let context = EvmTransactionCheckerContext {
            transaction: &transaction,
        };
        let checker = Erc20TransferChecker {};
        let result = checker.run(&context).await?;
        
        assert!(!result.warnings.is_empty(), "warning on ERC20 transferFrom to zero address");
        Ok(())
    }
}

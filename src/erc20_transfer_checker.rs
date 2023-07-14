use async_trait::async_trait;

use crate::types::{
    EvmTransactionChecker, EvmTransactionCheckerContext, EvmTransactionCheckerResult,
};

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
        let result = EvmTransactionCheckerResult::default();

        //TODO: Your code here

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

    // TODO: Actual tests
}

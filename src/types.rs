use async_trait::async_trait;

#[derive(Debug)]
pub struct EvmTransactionObject {
    pub from: Option<String>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub data: Option<String>,
    pub gas: Option<String>,
}

#[derive(Default, Debug)]
pub struct EvmTransactionCheckerResult {
    pub warnings: Vec<String>,
}

pub struct EvmTransactionCheckerContext<'a> {
    pub transaction: &'a EvmTransactionObject,
}

/// This is a general trait we use for all EVM transaction checkers
#[async_trait]
pub trait EvmTransactionChecker: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(
        &self,
        context: &EvmTransactionCheckerContext,
    ) -> anyhow::Result<EvmTransactionCheckerResult>;
}

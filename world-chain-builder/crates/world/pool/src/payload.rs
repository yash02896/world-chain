use bon::builder;

#[builder(on(String, into))]
pub fn build_pbh_tx(
    #[builder(default = "test test test test test test test test test test test junk")]
    mnemonic: String,

    user_ops: Vec<String>,
) {
}

#[builder(on(String, into))]
pub fn build_user_op() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatever() {
        // build_pbh_tx().call();
    }
}

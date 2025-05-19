#[macro_export]
macro_rules! map {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {
        &std::collections::HashMap::from([
            $( ($key.to_string(), ::serde_json::Value::from($value)), )*
        ])
    };
}

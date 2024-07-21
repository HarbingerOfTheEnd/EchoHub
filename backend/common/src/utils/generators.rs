use std::{
    env::var,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

const EPOCH: u64 = 1_704_067_200_000;
static GENERATED_IDS: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    static ref EH_WORKER_ID: u64 = {
        let worker_id = var("EH_WORKER_ID").unwrap_or("0".to_string());
        worker_id.parse::<u64>().unwrap_or_default()
    };
    static ref EH_PROCESS_ID: u64 = {
        let process_id = var("EH_PROCESS_ID").unwrap_or("0".to_string());
        process_id.parse::<u64>().unwrap_or_default()
    };
    static ref SNOWFLAKE_BASE: u64 = (*EH_WORKER_ID << 17) + (*EH_PROCESS_ID << 12);
}

pub fn generate_snowflake(now: u64) -> u64 {
    let generated_ids = GENERATED_IDS.load(Relaxed);

    *SNOWFLAKE_BASE
        + GENERATED_IDS.fetch_add((1 + generated_ids) % 4096, Relaxed)
        + ((now - EPOCH) << 22)
}

#[cfg(test)]
pub mod tests {
    use crate::utils::now_millis;

    use super::*;

    #[test]
    fn test_generate_snowflake() {
        let now = now_millis() as u64;
        let snowflake = generate_snowflake(now);

        eprintln!("{snowflake}: {now}: {:}", now - EPOCH);

        assert_eq!(EPOCH + (snowflake >> 22), now);
        assert_eq!(GENERATED_IDS.load(Relaxed), 1)
    }
}

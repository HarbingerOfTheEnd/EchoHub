use std::{
    env::var,
    sync::atomic::{AtomicU64, Ordering::SeqCst},
};

use lazy_static::lazy_static;
use time::OffsetDateTime;

const EPOCH: u64 = 1_735_689_600_000;
lazy_static! {
    static ref SNOWFLAKE_BASE: u64 = {
        let worker = var("EH_WORKER_ID")
            .expect("EH_WORKER_ID not set")
            .parse::<u64>()
            .expect("EH_WORKER_ID invalid");
        let process = var("EH_PROCESS_ID")
            .expect("EH_PROCESS_ID not set")
            .parse::<u64>()
            .expect("EH_PROCESS_ID invalid");
        (worker << 17) + (process << 12)
    };
}
static GENERATED_IDS: AtomicU64 = AtomicU64::new(0);

pub fn generate_snowflake(now: u64) -> String {
    let generated_id = GENERATED_IDS.load(SeqCst);
    let seq = GENERATED_IDS.fetch_add((1 + generated_id) % 4096, SeqCst);
    let timestamp = (now - EPOCH) << 22;
    let id = *SNOWFLAKE_BASE + seq + timestamp;
    id.to_string()
}

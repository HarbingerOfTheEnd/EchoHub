use core::hash;
use std::{
    env::var,
    sync::atomic::{AtomicU64, Ordering::SeqCst},
    thread::current,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use entity::users;
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

const EPOCH: u64 = 1_735_689_600_000;
pub const ACCESS_TOKEN_EXPIRES_IN: u64 = 60 * 60 * 24 * 30 * 2;
pub const REFRESH_TOKEN_EXPIRES_IN: u64 = 60 * 60 * 24 * 30 * 6;
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

pub fn generate_token(user: &users::Model) -> String {
    let user_id_part = STANDARD.encode(user.id.as_bytes());
    let unique_part = format!(
        "{}{}",
        current().name().unwrap_or("unnamed"),
        OffsetDateTime::now_utc().unix_timestamp(),
    );
    let unique_part = STANDARD.encode(unique_part.as_bytes());
    let random_part = Uuid::new_v4().simple().to_string();

    let mut hasher = Sha256::new();
    hasher.update(unique_part);
    hasher.update(b".");
    hasher.update(random_part);
    let hash = STANDARD.encode(hasher.finalize().as_slice());

    format!("{user_id_part}.{hash}")
        .replace("+", "_")
        .replace("/", "-")
}

pub fn generate_token_pair(user: &users::Model) -> (String, String) {
    let access_token = generate_token(user);
    let refresh_token = generate_token(user);
    (access_token, refresh_token)
}

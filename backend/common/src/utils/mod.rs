use time::OffsetDateTime;

pub mod email;
pub mod generators;

#[inline(always)]
pub fn now_millis() -> u64 {
    (OffsetDateTime::now_utc().unix_timestamp() * 1_000) as u64
}

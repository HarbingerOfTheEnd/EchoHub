use std::{
    collections::HashMap,
    env::var,
    sync::atomic::{AtomicU64, Ordering::SeqCst},
    thread::current,
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use entity::{oauth2_token_pairs, users};
use jsonwebtoken::{
    Algorithm::HS256, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use lazy_static::lazy_static;
use lettre::{Message, SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use sea_orm::{ActiveValue::Set, DbConn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::task::spawn_blocking;
use uuid::Uuid;

use super::{db::Mutation, enums::scope::Scope};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    user_id: String,
    exp: usize,
}

impl From<HashMap<String, Value>> for Claims {
    fn from(value: HashMap<String, Value>) -> Self {
        let user_id = value
            .get("user_id")
            .unwrap_or(&Value::String("".to_string()))
            .as_str()
            .unwrap()
            .to_string();
        let exp = value
            .get("exp")
            .unwrap_or(&Value::Number(0.into()))
            .as_i64()
            .unwrap_or(0);

        let exp = OffsetDateTime::now_utc()
            .checked_add(Duration::seconds(exp))
            .expect("valid timestamp")
            .unix_timestamp() as usize;

        Self { user_id, exp }
    }
}

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

pub fn generate_token(user_id: &str) -> String {
    let user_id_part = STANDARD.encode(user_id.as_bytes());
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

pub fn generate_token_pair(user_id: &str) -> (String, String) {
    let access_token = generate_token(user_id);
    let refresh_token = generate_token(user_id);

    (access_token, refresh_token)
}

pub async fn send_email(to: &str, subject: &str, body: &str) -> Result<()> {
    let from = var("EH_EMAIL").context("EH_EMAIL not set")?;
    let password = var("EH_EMAIL_PASSWORD").context("EH_EMAIL_PASSWORD not set")?;
    let smtp_server = "smtp.gmail.com";
    let smtp_port = 587;

    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .body(String::from(body))?;

    let mailer = SmtpTransport::relay(smtp_server)
        .context("Failed to create SMTP transport")?
        .port(smtp_port)
        .credentials(Credentials::new(from.clone(), password))
        .build();

    spawn_blocking(move || {
        mailer.send(&email);
    })
    .await?;

    Ok(())
}

pub fn generate_jwt_token(claims: &HashMap<String, Value>) -> Result<String> {
    let header = Header::new(HS256);
    let claims = Claims::from(claims.clone());
    let secret = var("EH_JWT_SECRET").context("EH_JWT_SECRET not set")?;
    let key = EncodingKey::from_secret(secret.as_ref());

    encode(&header, &claims, &key).context("Failed to encode JWT token")
}

pub fn parse_jwt_token(token: &str) -> Result<HashMap<String, Value>> {
    let secret = var("EH_JWT_SECRET").context("EH_JWT_SECRET not set")?;
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(HS256);

    let token = decode(token, &key, &validation).context("Failed to decode JWT token")?;

    return Ok(token.claims);
}

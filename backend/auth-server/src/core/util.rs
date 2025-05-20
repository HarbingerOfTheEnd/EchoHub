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
use lettre::{
    Message, SmtpTransport, Transport, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use once_cell::sync::Lazy;
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

pub const EPOCH: u64 = 1_735_689_600_000;
pub const ACCESS_TOKEN_EXPIRES_IN: u64 = 60 * 60 * 24 * 30 * 2;
pub const REFRESH_TOKEN_EXPIRES_IN: u64 = 60 * 60 * 24 * 30 * 6;

static SNOWFLAKE_BASE: Lazy<u64> = Lazy::new(|| {
    let worker = var("EH_WORKER_ID")
        .expect("EH_WORKER_ID not set")
        .parse::<u64>()
        .expect("EH_WORKER_ID invalid");
    let process = var("EH_PROCESS_ID")
        .expect("EH_PROCESS_ID not set")
        .parse::<u64>()
        .expect("EH_PROCESS_ID invalid");
    (worker << 17) + (process << 12)
});
static FROM: Lazy<String> = Lazy::new(|| var("EH_EMAIL").expect("EH_EMAIL not set"));
static MAILER: Lazy<SmtpTransport> = Lazy::new(|| {
    let smtp_server = var("EH_SMTP_SERVER").expect("EH_SMTP_SERVER not set");
    let smtp_port = var("EH_SMTP_PORT")
        .expect("EH_SMTP_PORT not set")
        .parse::<u16>()
        .expect("EH_SMTP_PORT invalid");
    let from = FROM.clone();
    let password = var("EH_EMAIL_PASSWORD").expect("EH_EMAIL_PASSWORD not set");

    SmtpTransport::starttls_relay(&smtp_server)
        .expect("Failed to create SMTP transport")
        .port(smtp_port)
        .credentials(Credentials::new(from, password))
        .build()
});
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

pub async fn send_email(to: &str, subject: &str, body: String) -> Result<()> {
    let from = FROM.clone();

    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(body)?;

    spawn_blocking(move || MAILER.send(&email).context("Failed to send email"))
        .await
        .context("Unable to send")?
        .context("Failed to send email")?;

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
#[cfg(test)]
mod tests {
    use std::{
        env::{remove_var, set_var},
        sync::Once,
    };

    use serde_json::json;

    use super::*;

    static INIT: Once = Once::new();

    fn setup_env() {
        INIT.call_once(|| unsafe {
            set_var("EH_WORKER_ID", "1");
            set_var("EH_PROCESS_ID", "2");
            set_var("EH_EMAIL", "test@example.com");
            set_var("EH_SMTP_SERVER", "smtp.example.com");
            set_var("EH_SMTP_PORT", "587");
            set_var("EH_EMAIL_PASSWORD", "password");
            set_var("EH_JWT_SECRET", "supersecretkey");
        });
    }

    #[test]
    fn test_claims_from_hashmap() {
        let mut map = HashMap::new();
        map.insert("user_id".to_string(), json!("user123"));
        map.insert("exp".to_string(), json!(3600));
        let claims = Claims::from(map);
        assert_eq!(claims.user_id, "user123");
        assert!(claims.exp > 0);
    }

    #[test]
    fn test_claims_from_hashmap_missing_fields() {
        let map = HashMap::new();
        let claims = Claims::from(map);
        assert_eq!(claims.user_id, "");
        assert!(claims.exp > 0);
    }

    #[test]
    fn test_generate_snowflake_unique() {
        setup_env();
        let now = EPOCH + 100_000;
        let id1 = generate_snowflake(now);
        let id2 = generate_snowflake(now + 1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_generate_token_format() {
        let token = generate_token("user123");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 2);
        let decoded = STANDARD.decode(parts[0]).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "user123");
    }

    #[test]
    fn test_generate_token_pair_unique() {
        let (access, refresh) = generate_token_pair("user123");
        assert_ne!(access, refresh);
    }

    #[tokio::test]
    async fn test_send_email_invalid_address() {
        setup_env();
        let result = send_email("invalid", "Subject", String::from("Body")).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_jwt_token_and_parse() {
        setup_env();
        let mut claims = HashMap::new();
        claims.insert("user_id".to_string(), json!("user123"));
        claims.insert("exp".to_string(), json!(3600));
        let token = generate_jwt_token(&claims).unwrap();
        let parsed = parse_jwt_token(&token).unwrap();
        assert_eq!(parsed.get("user_id").unwrap(), "user123");
    }

    #[test]
    fn test_generate_jwt_token_missing_secret() {
        let mut claims = HashMap::new();
        claims.insert("user_id".to_string(), json!("user123"));
        claims.insert("exp".to_string(), json!(3600));
        let old = var("EH_JWT_SECRET").ok();
        unsafe {
            remove_var("EH_JWT_SECRET");
        }
        let result = generate_jwt_token(&claims);
        assert!(result.is_err());
        if let Some(val) = old {
            unsafe {
                set_var("EH_JWT_SECRET", val);
            }
        }
    }

    #[test]
    fn test_parse_jwt_token_invalid() {
        setup_env();
        let result = parse_jwt_token("invalid.token.here");
        assert!(result.is_err());
    }
}

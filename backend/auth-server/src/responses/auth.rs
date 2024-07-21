#[cfg(test)]
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub struct OAuth2TokenResponse<'a> {
    pub token_type: &'a str,
    pub access_token: &'a str,
    pub refresh_token: &'a str,
    pub expires_in: i64,
    pub scope: &'a str,
}

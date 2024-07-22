use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize, Default))]
pub struct SignupRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[cfg(test)]
impl From<SignupRequest> for axum::body::Body {
    fn from(buf: SignupRequest) -> Self {
        serde_json::to_string(&buf).unwrap().into()
    }
}

use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize, Default))]
pub struct SignupRequest<'a> {
    pub email: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

#[cfg(test)]
impl<'a> From<SignupRequest<'a>> for axum::body::Body {
    fn from(buf: SignupRequest) -> Self {
        serde_json::to_string(&buf).unwrap().into()
    }
}

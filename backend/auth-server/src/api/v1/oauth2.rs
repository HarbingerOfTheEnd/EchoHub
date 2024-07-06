pub async fn authorize() -> &'static str {
    "Hello, OAuth2!"
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use hyper::StatusCode;
    use tower::ServiceExt;

    use crate::prelude::app;

    #[tokio::test]
    async fn test_authorize() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/oauth/authorize")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

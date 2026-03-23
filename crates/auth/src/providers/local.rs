use async_trait::async_trait;

use crate::provider::AuthProvider;

pub struct LocalAuthProvider {
    pub password: Option<String>,
}

#[async_trait]
impl AuthProvider for LocalAuthProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    fn redirect_url(&self, _callback_url: &str, _state: &str) -> Option<String> {
        None
    }

    async fn exchange_code(&self, _code: &str, _callback_url: &str) -> Result<String, String> {
        Err("local provider does not support IdP code exchange".to_string())
    }

    fn check_password(&self, provided: &str) -> bool {
        match &self.password {
            None => true,
            Some(expected) => provided == expected.as_str(),
        }
    }

    fn needs_password(&self) -> bool {
        self.password.is_some()
    }
}

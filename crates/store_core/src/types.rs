use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SandboxStatus {
    Running,
    Suspended,
}

impl std::fmt::Display for SandboxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxStatus::Running => write!(f, "running"),
            SandboxStatus::Suspended => write!(f, "suspended"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingCodeRecord {
    /// Unix timestamp (seconds) after which this code is expired.
    pub expire_at: i64,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub owner_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingAuthRecord {
    /// Unix timestamp (seconds) after which this request is expired.
    pub expire_at: i64,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub client_state: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SandboxRecord {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub work_dir: String,
    pub owner_key: String,
    /// Unix timestamp (seconds) when the sandbox was created.
    pub created_at: i64,
    pub status: SandboxStatus,
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

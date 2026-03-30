use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RookCommand {
    ReadFile {
        req_id: u64,
        path: String,
        offset: Option<u32>,
        limit: Option<u32>,
    },
    WriteFile {
        req_id: u64,
        path: String,
        content: String,
    },
    EditFile {
        req_id: u64,
        path: String,
        old_string: String,
        new_string: String,
    },
    Glob {
        req_id: u64,
        pattern: String,
        base_path: Option<String>,
    },
    Grep {
        req_id: u64,
        pattern: String,
        path: Option<String>,
        include: Option<String>,
    },
    RunCommand {
        req_id: u64,
        command: String,
        dir: Option<String>,
        env: HashMap<String, String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RookResponse {
    Hello { sandbox_id: String },
    Result { req_id: u64, output: String },
    Output { req_id: u64, line: String },
    Done { req_id: u64, exit_code: i32 },
    Error { req_id: u64, message: String },
}

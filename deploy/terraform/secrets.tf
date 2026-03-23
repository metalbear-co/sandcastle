# App credentials stored in Secret Manager — values set manually after first apply.

resource "google_secret_manager_secret" "db_password" {
  secret_id = "sandcastle-db-password"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "github_oauth_client_id" {
  secret_id = "sandcastle-github-oauth-client-id"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "github_oauth_client_secret" {
  secret_id = "sandcastle-github-oauth-client-secret"
  replication {
    auto {}
  }
}

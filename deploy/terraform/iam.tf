resource "google_service_account" "sandcastle" {
  account_id   = "sandcastle-svc"
  display_name = "Sandcastle Cloud Run service account"
}

# Connect to Cloud SQL
resource "google_project_iam_member" "sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.sandcastle.email}"
}

# Read app credentials from Secret Manager
resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.sandcastle.email}"
}

# Create and manage per-user secrets in Secret Manager
resource "google_project_iam_member" "secret_admin" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.sandcastle.email}"
}

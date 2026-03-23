locals {
  image = "${var.region}-docker.pkg.dev/${var.project_id}/sandcastle/sandcastle:${var.image_tag}"
  db_connection_name = google_sql_database_instance.sandcastle.connection_name
  # Cloud SQL Unix socket URL — no proxy needed in Cloud Run
  database_url = "postgresql:///${var.db_name}?host=/cloudsql/${local.db_connection_name}&user=${var.db_user}&password=${data.google_secret_manager_secret_version.db_password.secret_data}"
}

resource "google_cloud_run_v2_service" "sandcastle" {
  name     = var.service_name
  location = var.region

  template {
    service_account = google_service_account.sandcastle.email

    # Connect to Cloud SQL via Unix socket (no sidecar needed)
    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [local.db_connection_name]
      }
    }

    containers {
      image = local.image

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      env {
        name  = "STORAGE_BACKEND"
        value = "postgres"
      }
      env {
        name  = "SECRET_BACKEND"
        value = "gcp"
      }
      env {
        name  = "DATABASE_URL"
        value = local.database_url
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "AUTH_PROVIDER"
        value = "github"
      }
      env {
        name = "GITHUB_OAUTH_CLIENT_ID"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.github_oauth_client_id.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "GITHUB_OAUTH_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.github_oauth_client_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "SANDCASTLE_PROVIDERS"
        value = "daytona"
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [
    google_project_iam_member.sql_client,
    google_project_iam_member.secret_accessor,
    google_project_iam_member.secret_admin,
  ]
}

# Allow unauthenticated invocations (MCP clients authenticate via OAuth)
resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = google_cloud_run_v2_service.sandcastle.project
  location = google_cloud_run_v2_service.sandcastle.location
  name     = google_cloud_run_v2_service.sandcastle.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "service_url" {
  value       = google_cloud_run_v2_service.sandcastle.uri
  description = "Cloud Run service URL — set as BASE_URL in subsequent deploys"
}

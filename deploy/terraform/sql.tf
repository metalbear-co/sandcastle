resource "google_sql_database_instance" "sandcastle" {
  name             = var.db_instance_name
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier = "db-f1-micro"

    backup_configuration {
      enabled = true
    }

    ip_configuration {
      ipv4_enabled = false
    }
  }

  deletion_protection = true
}

resource "google_sql_database" "sandcastle" {
  name     = var.db_name
  instance = google_sql_database_instance.sandcastle.name
}

resource "google_sql_user" "sandcastle" {
  name     = var.db_user
  instance = google_sql_database_instance.sandcastle.name
  password = data.google_secret_manager_secret_version.db_password.secret_data
}

data "google_secret_manager_secret_version" "db_password" {
  secret  = google_secret_manager_secret.db_password.secret_id
  version = "latest"
}

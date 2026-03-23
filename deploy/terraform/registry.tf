resource "google_artifact_registry_repository" "sandcastle" {
  location      = var.region
  repository_id = "sandcastle"
  format        = "DOCKER"
  description   = "Sandcastle container images"
}

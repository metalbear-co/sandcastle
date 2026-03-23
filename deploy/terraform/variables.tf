variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run and Cloud SQL"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run service name"
  type        = string
  default     = "sandcastle"
}

variable "image_tag" {
  description = "Docker image tag to deploy (e.g. sha-abc1234)"
  type        = string
}

variable "db_instance_name" {
  description = "Cloud SQL instance name"
  type        = string
  default     = "sandcastle-postgres"
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "sandcastle"
}

variable "db_user" {
  description = "PostgreSQL user"
  type        = string
  default     = "sandcastle"
}

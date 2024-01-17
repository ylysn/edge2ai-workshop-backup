provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  zone    = "${var.gcp_region}-${var.gcp_az}"
  default_labels = {
    owner   = replace(replace(lower(var.owner), ".", "-"), " ", "_")
    project = replace(replace(lower(var.project), ".", "-"), " ", "_")
    enddate = var.enddate
  }
}

provider "null" {
}

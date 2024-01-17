resource "google_compute_network" "vpc" {
  count                           = (var.vpc_id != "" ? 0 : 1)
  name                            = "${var.owner}-${var.name_prefix}-vpc"
  auto_create_subnetworks         = false
  delete_default_routes_on_create = true
}

resource "google_compute_subnetwork" "subnet1" {
  network       = (var.vpc_id != "" ? var.vpc_id : google_compute_network.vpc[0].self_link)
  name          = "${var.owner}-${var.name_prefix}-subnet1"
  ip_cidr_range = var.cidr_block_1
  region        = var.gcp_region
}

resource "google_compute_route" "route" {
  network          = google_compute_network.vpc[0].self_link
  name             = "${var.owner}-${var.name_prefix}-egress-internet"
  description      = "route through IGW to access internet"
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "default-internet-gateway"
}


# centos boot script on GCP
locals {
  init_script = <<-EOF
  #!/bin/bash
  # centos-cloud image post-fix script
  # - set hostname
  # - add centos user
  # - allow root access
  hostnamectl set-hostname %s --static
  CONF="/etc/workshop.conf"
  if [[ ! -f $CONF ]]; then
    #initialization on first boot
    useradd -G 4,39,1000 centos
    AUTH_KEYS='%s'
    mkdir /home/centos/.ssh
    touch /home/centos/.ssh/authorized_keys
    chmod 0600 /home/centos/.ssh/authorized_keys
    chown -R centos:centos /home/centos/.ssh
    echo $AUTH_KEYS >> /home/centos/.ssh/authorized_keys
    sed -i.bak 's/PermitRootLogin *no/PermitRootLogin yes/' /etc/ssh/sshd_config
    echo "export CLUSTER_ID=%s" >> $CONF
  fi
  EOF
}

# cluster block
resource "google_compute_instance" "cluster" {
  count                   = var.cluster_count
  name                    = "${var.owner}-${var.name_prefix}-cluster-${count.index}"
  machine_type            = var.cluster_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  metadata_startup_script = format(local.init_script,"cdp.${google_compute_address.cluster-public-ip[count.index].address}.nip.io",file(var.ssh_public_key), count.index)
  hostname                = "cdp.${google_compute_address.cluster-public-ip[count.index].address}.nip.io"

  tags = [
    "${var.owner}-${var.name_prefix}-private-access",
    "${var.owner}-${var.name_prefix}-workshop-cross-access",
    "${var.owner}-${var.name_prefix}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.cluster_ami
      size  = 200
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  attached_disk {
    source      = google_compute_disk.cluster-pd[count.index].self_link
    device_name = "${var.owner}-${var.name_prefix}-cluster-pd-${count.index}-disk-0"
    mode        = "READ_WRITE"
  }

  metadata = {
    ssh-keys = "${var.owner}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.cluster-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }

}

resource "google_compute_disk" "cluster-pd" {
  count = var.cluster_count
  name  = "${var.owner}-${var.name_prefix}-cluster-pd-${count.index}"
  type  = "pd-balanced"
  zone  = "${var.gcp_region}-${var.gcp_az}"
  size  = 200
}

resource "google_compute_address" "cluster-public-ip" {
  count        = var.cluster_count
  name         = "${var.owner}-${var.name_prefix}-cluster-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# web block
resource "google_compute_instance" "web" {
  count                   = (var.launch_web_server ? 1 : 0)
  name                    = "${var.owner}-${var.name_prefix}-web"
  machine_type            = "e2-standard-2"
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  metadata_startup_script = format(local.init_script,"web.${google_compute_address.web-public-ip[count.index].address}.nip.io",file(var.web_ssh_public_key), count.index)
  hostname                = "web.${google_compute_address.web-public-ip[count.index].address}.nip.io"

  tags = [
    "${var.owner}-${var.name_prefix}-private-access",
    "${var.owner}-${var.name_prefix}-web-access",
  ]

  boot_disk {
    initialize_params {
      image = var.cluster_ami
      size  = 20
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  metadata = {
    ssh-keys = "${var.owner}:${file(var.web_ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.web-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }

}

resource "google_compute_address" "web-public-ip" {
  count        = (var.launch_web_server ? 1 : 0)
  name         = "${var.owner}-${var.name_prefix}-web-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# ipa block
resource "google_compute_instance" "ipa" {
  count                   = (var.use_ipa ? 1 : 0)
  name                    = "${var.owner}-${var.name_prefix}-ipa"
  machine_type            = "e2-standard-2"
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  metadata_startup_script = format(local.init_script,"ipa.${google_compute_address.ipa-public-ip[count.index].address}.nip.io",file(var.ssh_public_key), count.index)
  hostname                = "ipa.${google_compute_address.ipa-public-ip[count.index].address}.nip.io"

  tags = [
    "${var.owner}-${var.name_prefix}-private-access",
    "${var.owner}-${var.name_prefix}-workshop-cross-access",
    "${var.owner}-${var.name_prefix}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.cluster_ami
      size  = 20
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  metadata = {
    ssh-keys = "${var.owner}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.ipa-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }

}


resource "google_compute_address" "ipa-public-ip" {
  count        = (var.use_ipa ? 1 : 0)
  name         = "${var.owner}-${var.name_prefix}-ipa-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# ecs block
resource "google_compute_instance" "ecs" {
  count                   = (var.pvc_data_services ? var.cluster_count : 0)
  name                    = "${var.owner}-${var.name_prefix}-ecs-${count.index}"
  machine_type            = var.ecs_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  metadata_startup_script = format(local.init_script,"ecs.${google_compute_address.ecs-public-ip[count.index].address}.nip.io",file(var.ssh_public_key), count.index)
  hostname                = "ecs.${google_compute_address.ecs-public-ip[count.index].address}.nip.io"

  tags = [
    "${var.owner}-${var.name_prefix}-private-access",
    "${var.owner}-${var.name_prefix}-workshop-cross-access",
    "${var.owner}-${var.name_prefix}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.ecs_ami
      size  = 500
      type  = "pd-balanced"
    }
    auto_delete = true
  }


  metadata = {
    ssh-keys = "${var.owner}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.ecs-public-ip[count.index].address
    }
  }


  timeouts {
    create = "10m"
  }

}

resource "google_compute_address" "ecs-public-ip" {
  count        = (var.pvc_data_services ? var.cluster_count : 0)
  name         = "${var.owner}-${var.name_prefix}-ecs-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# GCP instance group
resource "google_compute_instance_group" "servers" {
  name        = "${var.owner}-${var.name_prefix}-servers"
  description = "${var.project}"

  instances = flatten([
    [for id in (google_compute_instance.cluster.*.id): id],
    [for id in (google_compute_instance.ecs.*.id): id],
    [for id in (google_compute_instance.web.*.id): id],
    [for id in (google_compute_instance.ipa.*.id): id],
    [for id in (google_compute_instance.ocp.*.id): id],
  ])

  zone = "${var.gcp_region}-${var.gcp_az}"
}

# ocp block
resource "google_compute_instance" "ocp" {
  count                   = (var.deploy_ocp ? var.cluster_count : 0)
  name                    = "${var.owner}-${var.name_prefix}-ocp-${count.index}"
  machine_type            = var.ocp_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  metadata_startup_script = format(local.rocky_init_script,"ocp.${google_compute_address.ocp-public-ip[count.index].address}.nip.io",file(var.ssh_public_key), count.index)
  hostname                = "ocp.${google_compute_address.ocp-public-ip[count.index].address}.nip.io"
  
  advanced_machine_features {
    enable_nested_virtualization = true
  }
  
  tags = [
    "${var.owner}-${var.name_prefix}-private-access",
    "${var.owner}-${var.name_prefix}-workshop-cross-access",
    "${var.owner}-${var.name_prefix}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.ocp_ami
      size  = 500
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  metadata = {
    ssh-keys = "${var.owner}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.ocp-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }
}

resource "google_compute_address" "ocp-public-ip" {
  count        = (var.deploy_ocp ? var.cluster_count : 0)
  name         = "${var.owner}-${var.name_prefix}-ocp-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# rocky boot script on GCP
locals {
  rocky_init_script = <<-EOF
  #!/bin/bash
  # rocky-cloud image post-fix script
  # - set hostname
  # - add rocky user
  # - allow root access
  hostnamectl set-hostname %s --static
  CONF="/etc/workshop.conf"
  if [[ ! -f $CONF ]]; then
    #initialization on first boot
    useradd -G 4,39,1000 rocky
    AUTH_KEYS='%s'
    mkdir /home/rocky/.ssh
    touch /home/rocky/.ssh/authorized_keys
    chmod 0600 /home/rocky/.ssh/authorized_keys
    chown -R rocky:rocky /home/rocky/.ssh
    echo $AUTH_KEYS >> /home/rocky/.ssh/authorized_keys
    sed -i.bak 's/PermitRootLogin *no/PermitRootLogin yes/' /etc/ssh/sshd_config
    echo "export CLUSTER_ID=%s" >> $CONF
  fi
  EOF
}
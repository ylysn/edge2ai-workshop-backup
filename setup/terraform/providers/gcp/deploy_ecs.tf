resource "null_resource" "deploy_ecs" {
  count = (var.pvc_data_services ? var.cluster_count : 0)

  depends_on = [
    google_compute_instance.ecs
  ]

  connection {
    host        = element( google_compute_address.ecs-public-ip.*.address, count.index)
    type        = "ssh"
    user        = var.ssh_username
    private_key = file(var.ssh_private_key)
  }

  provisioner "file" {
    source      = "${var.base_dir}/resources"
    destination = "/tmp/"
  }

  provisioner "remote-exec" {
    inline = [
      "set -o errexit",
      "set -o xtrace",
      "sudo nohup bash -x /tmp/resources/setup-ecs.sh install-prereqs gcp \"${var.ssh_username}\" \"${var.ssh_password}\" \"${var.namespace}\" \"${(var.use_ipa ? "ipa.${google_compute_address.ipa-public-ip[0].address}.nip.io" : "")}\" \"${(var.use_ipa ? google_compute_instance.ipa[0].network_interface.0.network_ip : "")}\" > /tmp/resources/setup-ecs.install-prereqs.log 2>&1 &",
      "sleep 1 # don't remove - needed for the nohup to work",
    ]
  }
}

